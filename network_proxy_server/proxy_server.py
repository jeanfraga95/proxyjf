#!/usr/bin/env python3

import asyncio
import json
import os
import sys
import ssl
import websockets
import logging

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def setup_logging(log_to_file=False, log_file_path="./network_proxy_server/logs/proxy.log"):
    # Remove existing handlers to prevent duplicate logs
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Add stream handler for console output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(console_handler)

    if log_to_file:
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(file_handler)

# Global dictionary to store active proxy processes (for in-memory tracking)
active_proxies = {}

# Persistence file path
PERSISTENCE_FILE = "./network_proxy_server/config/active_proxies.json"

async def save_active_proxies():
    os.makedirs(os.path.dirname(PERSISTENCE_FILE), exist_ok=True)
    with open(PERSISTENCE_FILE, "w") as f:
        json.dump(active_proxies, f, indent=4)
    logger.info("Estado dos proxies ativos salvo.")

async def load_active_proxies():
    global active_proxies
    if os.path.exists(PERSISTENCE_FILE):
        with open(PERSISTENCE_FILE, "r") as f:
            active_proxies = json.load(f)
        logger.info("Os proxies ativos estão carregados.")
    else:
        active_proxies = {}
        logger.info("Nenhum estado de proxy ativo existente foi encontrado.")

async def transfer_data(reader, writer, log_prefix):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception as e:
        logger.error(f"{log_prefix} Data transfer error: {e}")
    finally:
        writer.close()

async def generate_self_signed_cert(cert_path, key_path):
    logger.info(f"Generating self-signed certificate at {cert_path} and key at {key_path}")
    # Ensure the directory exists
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    # Generate private key
    proc_key = await asyncio.create_subprocess_shell(
        f"openssl genrsa -out {key_path} 2048",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout_key, stderr_key = await proc_key.communicate()
    if proc_key.returncode != 0:
        logger.error(f"Failed to generate private key: {stderr_key.decode().strip()}")
        return False

    # Generate self-signed certificate
    proc_cert = await asyncio.create_subprocess_shell(
        f"openssl req -new -x509 -key {key_path} -out {cert_path} -days 365 -nodes -subj \"/CN=localhost\"",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout_cert, stderr_cert = await proc_cert.communicate()
    if proc_cert.returncode != 0:
        logger.error(f"Failed to generate self-signed certificate: {stderr_cert.decode().strip()}")
        return False

    logger.info("Self-signed certificate and key generated successfully.")
    return True

async def handle_socks5_protocol(reader, writer, initial_data=b""):
    addr = writer.get_extra_info("peername")
    logger.info(f"[SOCKS5 Protocol] Handling SOCKS5 protocol for {addr}")

    try:
        # Prepend initial data if any, then read the rest of the handshake
        data = initial_data + await reader.read(256) 
        if not data or data[0] != 0x05: # SOCKS Version 5
            logger.warning(f"[SOCKS5 Protocol] Invalid SOCKS version from {addr}")
            writer.close()
            return

        nmethods = data[1]
        methods = data[2:2+nmethods]

        if 0x00 not in methods: # No authentication required method
            logger.warning(f"[SOCKS5 Protocol] No acceptable authentication method from {addr}")
            writer.write(b'\x05\xFF') # SOCKS5, No acceptable methods
            await writer.drain()
            writer.close()
            return

        writer.write(b'\x05\x00') # SOCKS5, No authentication required
        await writer.drain()

        # SOCKS5 Handshake - Request
        data = await reader.read(256) # Read VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
        if not data or data[0] != 0x05: # SOCKS Version 5
            logger.warning(f"[SOCKS5 Protocol] Invalid SOCKS version in request from {addr}")
            writer.close()
            return

        cmd = data[1]
        if cmd != 0x01: # Only CONNECT command is supported
            logger.warning(f"[SOCKS5 Protocol] Unsupported SOCKS command {cmd} from {addr}")
            writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00') # Command not supported
            await writer.drain()
            writer.close()
            return

        target_host = '127.0.0.1'
        target_port = 22

        try:
            ssh_reader, ssh_writer = await asyncio.open_connection(target_host, target_port)
            logger.info(f"[SOCKS5 Protocol] Connected to OpenSSH at {target_host}:{target_port} for {addr}")
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x16') # SOCKS5, Success, BND.ADDR (127.0.0.1), BND.PORT (22)
            await writer.drain()

            await asyncio.gather(
                transfer_data(reader, ssh_writer, f"[SOCKS5->SSH] {addr}"),
                transfer_data(ssh_reader, writer, f"[SSH->SOCKS5] {addr}")
            )

        except ConnectionRefusedError:
            logger.error(f"[SOCKS5 Protocol] Connection to OpenSSH refused for {addr}")
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00') # Connection refused
            await writer.drain()
        except Exception as e:
            logger.error(f"[SOCKS5 Protocol] Error connecting to OpenSSH for {addr}: {e}")
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00') # General SOCKS server failure
            await writer.drain()

    except Exception as e:
        logger.error(f"[SOCKS5 Protocol] Error during SOCKS5 handshake for {addr}: {e}")
    finally:
        logger.info(f"[SOCKS5 Protocol] Closing connection for {addr}")
        writer.close()

async def handle_websocket_protocol(reader, writer, initial_data=b""):
    addr = writer.get_extra_info("peername")
    logger.info(f"[WebSocket Protocol] Handling WebSocket protocol for {addr}")

    target_host = '127.0.0.1'
    target_port = 22

    try:
        ssh_reader, ssh_writer = await asyncio.open_connection(target_host, target_port)
        logger.info(f"[WebSocket Protocol] Connected to OpenSSH at {target_host}:{target_port} for {addr}")

        # Send initial data to SSH if any
        if initial_data:
            ssh_writer.write(initial_data)
            await ssh_writer.drain()

        await asyncio.gather(
            transfer_data(reader, ssh_writer, f"[WS->SSH] {addr}"),
            transfer_data(ssh_reader, writer, f"[SSH->WS] {addr}")
        )

    except ConnectionRefusedError:
        logger.error(f"[WebSocket Protocol] Connection to OpenSSH refused for {addr}")
    except Exception as e:
        logger.error(f"[WebSocket Protocol] Error during WebSocket connection for {addr}: {e}")
    finally:
        logger.info(f"[WebSocket Protocol] Closing connection for {addr}")
        writer.close()

async def dispatch_connection(reader, writer):
    addr = writer.get_extra_info("peername")
    peer_port = writer.get_extra_info("sockname")[1] # Get the port the client connected to

    initial_data = b""
    try:
        # Read a small amount of data to sniff the protocol
        initial_data = await asyncio.wait_for(reader.read(4096), timeout=2) # Read up to 4KB, with a timeout

        # Check for HTTP/WebSocket signature
        # Check if it's an HTTP GET request and if it contains "Upgrade: websocket" header
        if b"GET / HTTP/1.1" in initial_data and b"Upgrade: websocket" in initial_data:
            logger.info(f"[Dispatcher] Detected HTTP/WebSocket signature from {addr}")
            response = b"HTTP/1.1 101 Proxy CloudJF\r\n\r\n"
            writer.write(response)
            await writer.drain()
            logger.info(f"[Dispatcher] Sent custom HTTP 101 CloudJF response to {addr}")
            await handle_websocket_protocol(reader, writer, initial_data)
            return

        # Check for SOCKS5 signature (starts with 0x05)
        elif initial_data.startswith(b'\x05'):
            logger.info(f"[Dispatcher] Detected SOCKS5 signature from {addr}")
            response = b"HTTP/1.1 200 OK\r\n\r\n"
            writer.write(response)
            await writer.drain()
            logger.info(f"[Dispatcher] Sent custom HTTP 200 OK response to {addr}")
            await handle_socks5_protocol(reader, writer, initial_data)
            return

        # Special handling for ports 443 and 8443 (treat as WebSocket)
        elif peer_port in [443, 8443]:
            logger.info(f"[Dispatcher] Connection on special port {peer_port} from {addr}. Treating as WebSocket.")
            response = b"HTTP/1.1 101 Proxy CloudJF\r\n\r\n"
            writer.write(response)
            await writer.drain()
            logger.info(f"[Dispatcher] Sent custom HTTP 101 CloudJF response to {addr} (special port). This will act as a raw tunnel.")
            await handle_websocket_protocol(reader, writer, initial_data)
            return

        else:
            logger.warning(f"[Dispatcher] Unknown protocol from {addr}. Initial data: {initial_data[:50]}...")
            writer.close()

    except asyncio.TimeoutError:
        logger.warning(f"[Dispatcher] Timeout waiting for initial data from {addr}. Closing connection.")
        writer.close()
    except Exception as e:
        logger.error(f"[Dispatcher] Error in dispatching connection from {addr}: {e}")
        writer.close()

async def start_socks5_proxy(port):
    server = await asyncio.start_server(dispatch_connection, '0.0.0.0', port)
    addr = server.sockets[0].getsockname()
    logger.info(f"[SOCKS5 Listener] Serving on {addr} (dispatches to SOCKS5 or WS)")
    async with server:
        await server.serve_forever()

async def start_websocket_proxy(port, use_wss=False, certfile=None, keyfile=None):
    # For WSS, we need to wrap the socket with SSL before dispatching
    if use_wss:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile, keyfile)
        server = await asyncio.start_server(dispatch_connection, "0.0.0.0", port, ssl=ssl_context)
        logger.info(f"[WSS Listener] Serving on 0.0.0.0:{port} with SSL (dispatches to SOCKS5 or WS)")
    else:
        server = await asyncio.start_server(dispatch_connection, "0.0.0.0", port)
        logger.info(f"[WS Listener] Serving on 0.0.0.0:{port} (dispatches to SOCKS5 or WS)")

    async with server:
        await server.serve_forever()

def generate_service_file(port, protocol, certfile=None, keyfile=None):
    service_name = f"proxyport@{port}.service"
    service_path = f"/etc/systemd/system/{service_name}"
    script_path = os.path.abspath(__file__)

    # Determine the command to run the proxy
    # The actual protocol handling is now done by dispatch_connection
    # The protocol argument here is mostly for systemd unit identification
    if protocol == "WS":
        exec_start = f"/usr/bin/env python3 {script_path} --protocol ws --port {port}"
    elif protocol == "WSS":
        exec_start = f"/usr/bin/env python3 {script_path} --protocol wss --port {port} --certfile {certfile} --keyfile {keyfile}"
    elif protocol == "SOCKS5":
        exec_start = f"/usr/bin/env python3 {script_path} --protocol socks5 --port {port}"
    else:
        raise ValueError("Unsupported protocol for service file generation.")

    content = f"""
[Unit]
Description=Proxy Service on Port {port} ({protocol})
After=network.target

[Service]
ExecStart={exec_start}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
"""
    return service_path, content

async def start_proxy_service(port, protocol, certfile=None, keyfile=None):
    service_path, content = generate_service_file(port, protocol, certfile, keyfile)
    service_name = os.path.basename(service_path)

    logger.info(f"Creating service file: {service_path}")
    # Write the service file (requires sudo)
    proc_write = await asyncio.create_subprocess_shell(
        f"echo \"{content}\" | sudo tee {service_path}"
    )
    await proc_write.wait()

    logger.info(f"Enabling and starting service: {service_name}")
    # Reload systemd, enable and start the service (requires sudo)
    proc_start = await asyncio.create_subprocess_shell(
        f"sudo systemctl daemon-reload && sudo systemctl enable {service_name} && sudo systemctl start {service_name}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc_start.communicate()
    if proc_start.returncode == 0:
        logger.info(f"Service {service_name} started successfully.")
        active_proxies[port] = {"protocol": protocol, "status": "running", "certfile": certfile, "keyfile": keyfile}
        await save_active_proxies() # Save state after modification
        return True
    else:
        logger.error(f"Failed to start service {service_name}. Error: {stderr.decode().strip()}")
        return False

async def stop_proxy_service(port):
    service_name = f"proxyport@{port}.service"
    service_path = f"/etc/systemd/system/{service_name}"

    logger.info(f"Stopping and disabling service: {service_name}")
    proc = await asyncio.create_subprocess_shell(
        f"sudo systemctl stop {service_name} && sudo systemctl disable {service_name} && sudo rm {service_path}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode == 0:
        logger.info(f"Service {service_name} parado e removido com sucesso.")
        if port in active_proxies:
            del active_proxies[port]
        await save_active_proxies() # Save state after modification
        return True
    else:
        logger.error(f"Falha ao interromper o serviço {service_name}. Error: {stderr.decode().strip()}")
        return False

async def show_menu():
    while True:
        print("\n--- Menu do Proxy CloudJF v1.0 ---")
        print("1. Abra nova porta")
        print("2. Fechar porta")
        print("3. Listar portas abertas")
        print("4. Sair")
        choice = input("Digite sua escolha: ")

        if choice == "1":
            await open_new_port_menu()
        elif choice == "2":
            await close_port_menu()
        elif choice == "3":
            await list_open_ports()
        elif choice == "4":
            logger.info("Saindo do menu. Os serviços em execução continuarão em segundo plano.")
            break
        else:
            print("Escolha inválida. Tente novamente.")

async def open_new_port_menu():
    print("\n--- Abrir nova porta no Proxy CloudJF ---")
    print("Escolha o protocolo:")
    print("1. WebSocket (WS)")
    print("2. WebSocket Secure (WSS)")
    print("3. SOCKS5")
    # print("4. Multiprotocol (WSS + SOCKS5) - Not yet implemented")
    protocol_choice = input("Insira a escolha do protocolo: ")

    try:
        port = int(input("Digite o número da porta: "))
        if not (1 <= port <= 65535):
            raise ValueError("O número da porta deve estar entre 1 e 65535.")
    except ValueError as e:
        logger.error(f"Número de porta inválido: {e}")
        return

    certfile = None
    keyfile = None

    if protocol_choice == "1": # WS
        logger.info(f"Abrindo proxy WS na porta {port}...")
        await start_proxy_service(port, "WS")
    elif protocol_choice == "2": # WSS
        cert_dir = "./network_proxy_server/certs"
        certfile = os.path.join(cert_dir, f"cert_{port}.pem")
        keyfile = os.path.join(cert_dir, f"key_{port}.pem")

        if not os.path.exists(certfile) or not os.path.exists(keyfile):
            logger.info(f"Certificado ou arquivo de chave não encontrado para a porta {porta}. Gerando novos.")
            if not await generate_self_signed_cert(certfile, keyfile):
                logger.error("Falha ao gerar certificado e chave. Abortando a inicialização do proxy WSS.")
                return
        else:
            logger.info(f"Usando certificado e chave existentes para porta {port}.")

        logger.info(f"Abrindo proxy WSS na porta {port}...")
        await start_proxy_service(port, "WSS", certfile=certfile, keyfile=keyfile)
    elif protocol_choice == "3": # SOCKS5
        logger.info(f"Abrindo proxy SOCKS5 na porta {port}...")
        await start_proxy_service(port, "SOCKS5")
    # elif protocol_choice == "4": # Multiprotocol
    #     print("Multiprotocol not yet implemented.")
    else:
        print("Escolha de protocolo inválida.")

async def close_port_menu():
    print("\n--- Fechar porta ---")
    if not active_proxies:
        print("Nenhum proxy ativo para fechar.")
        return

    print("Proxies ativos:")
    for port, details in active_proxies.items():
        print(f"  Porta: {port}, Protocolo: {details['protocol']}")

    try:
        port_to_close = int(input("Digite o número da porta para fechar: "))
        if port_to_close not in active_proxies:
            print("Porta não encontrada em proxies ativos.")
            return
        
        success = await stop_proxy_service(port_to_close)
        if success:
            logger.info(f"Proxy fechado com sucesso na porta {port_to_close}.")
        else:
            logger.error(f"Falha ao fechar o proxy na porta {port_to_close}.")

    except ValueError:
        logger.error("Número de porta inválido.")

async def list_open_ports():
    print("\n--- Status de portas abertas ---")
    if not active_proxies:
        print("Nenhum proxy é gerenciado atualmente por esta sessão.")
        print("Nota: Isso mostra apenas os proxies iniciados por meio deste menu na sessão atual.")
        print("Para o status de todo o sistema, verifique `sudo systemctl list-units --type=service | grep proxyport`")
        return

    print("Proxies managed by this session:")
    for port, details in active_proxies.items():
        print(f"  Port: {port}, Protocol: {details['protocol']}, Status: {details['status']}")

async def main():
    # Check for command-line arguments to run as a service
    if len(sys.argv) > 1 and sys.argv[1] == "--protocol":
        protocol = sys.argv[2]
        port = int(sys.argv[4])
        certfile = sys.argv[6] if "--certfile" in sys.argv else None
        keyfile = sys.argv[8] if "--keyfile" in sys.argv else None

        setup_logging(log_to_file=True)

        # The service will now always use dispatch_connection
        # The protocol argument here is mostly for logging/identification in systemd unit
        if protocol == "WS" or protocol == "WSS":
            await start_websocket_proxy(port, use_wss=(protocol == "WSS"), certfile=certfile, keyfile=keyfile)
        elif protocol == "SOCKS5":
            await start_socks5_proxy(port)
        else:
            logger.error(f"Unknown protocol: {protocol}")
            sys.exit(1)
    else:
        setup_logging() # Configure logging for interactive mode
        logger.info("Network Proxy Server - Initializing...")
        await load_active_proxies() # Load state on startup
        await show_menu()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nNetwork Proxy Server - Shutting down.")
    except Exception as e:
        logger.critical(f"An unhandled error occurred: {e}", exc_info=True)
        sys.exit(1)


