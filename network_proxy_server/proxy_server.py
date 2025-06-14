#!/usr/bin/env python3

import asyncio
import json
import os
import sys
import ssl
import socket
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

async def is_port_in_use(port):
    """Verifica se a porta está ocupada no sistema."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(0.5)
            s.bind(('', port))
        except OSError:
            return True
    return False

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
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def generate_self_signed_cert(cert_path, key_path):
    logger.info(f"Generating self-signed certificate at {cert_path} and key at {key_path}")
    # Ensure the directory exists
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    proc_key = await asyncio.create_subprocess_shell(
        f"openssl genrsa -out {key_path} 2048",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout_key, stderr_key = await proc_key.communicate()
    if proc_key.returncode != 0:
        logger.error(f"Failed to generate private key: {stderr_key.decode().strip()}")
        return False

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
        data = initial_data + await reader.read(256)
        if not data or data[0] != 0x05:
            logger.warning(f"[SOCKS5 Protocol] Invalid SOCKS version from {addr}")
            writer.close()
            await writer.wait_closed()
            return

        nmethods = data[1]
        methods = data[2:2+nmethods]

        if 0x00 not in methods:
            logger.warning(f"[SOCKS5 Protocol] No acceptable methods from {addr}")
            writer.write(b'\x05\xFF')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        writer.write(b'\x05\x00')
        await writer.drain()

        data = await reader.read(256)
        if not data or data[0] != 0x05:
            logger.warning(f"[SOCKS5 Protocol] Invalid SOCKS request from {addr}")
            writer.close()
            await writer.wait_closed()
            return

        cmd = data[1]
        if cmd != 0x01:
            logger.warning(f"[SOCKS5 Protocol] Unsupported command {cmd} from {addr}")
            writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        atyp = data[3]
        if atyp == 0x01:
            dst_addr = '.'.join(str(b) for b in data[4:8])
            dst_port = int.from_bytes(data[8:10], 'big')
        elif atyp == 0x03:
            domain_len = data[4]
            dst_addr = data[5:5+domain_len].decode()
            dst_port = int.from_bytes(data[5+domain_len:7+domain_len], 'big')
        elif atyp == 0x04:
            dst_addr = ':'.join(format(int.from_bytes(data[i:i+2],'big'),'x') for i in range(4,20,2))
            dst_port = int.from_bytes(data[20:22], 'big')
        else:
            logger.warning(f"[SOCKS5 Protocol] Unknown address type {atyp} from {addr}")
            writer.close()
            await writer.wait_closed()
            return

        logger.info(f"[SOCKS5 Protocol] Connecting to {dst_addr}:{dst_port} from {addr}")
        try:
            ssh_reader, ssh_writer = await asyncio.open_connection(dst_addr, dst_port)
            logger.info(f"[SOCKS5 Protocol] Connected to {dst_addr}:{dst_port}")
            reply = b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            writer.write(reply)
            await writer.drain()

            await asyncio.gather(
                transfer_data(reader, ssh_writer, f"[SOCKS5->DST] {addr}"),
                transfer_data(ssh_reader, writer, f"[DST->SOCKS5] {addr}")
            )
        except ConnectionRefusedError:
            logger.error(f"[SOCKS5 Protocol] Connection refused to {dst_addr}:{dst_port} from {addr}")
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
        except Exception as e:
            logger.error(f"[SOCKS5 Protocol] Error connecting to {dst_addr}:{dst_port} from {addr}: {e}")
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
    except Exception as e:
        logger.error(f"[SOCKS5 Protocol] SOCKS5 handshake error for {addr}: {e}")
    finally:
        logger.info(f"[SOCKS5 Protocol] Closing connection for {addr}")
        writer.close()
        await writer.wait_closed()

async def handle_websocket_protocol(reader, writer, initial_data=b""):
    addr = writer.get_extra_info("peername")
    logger.info(f"[WebSocket Protocol] Handling WebSocket protocol for {addr}")

    target_host = '127.0.0.1'
    target_port = 22

    try:
        ssh_reader, ssh_writer = await asyncio.open_connection(target_host, target_port)
        logger.info(f"[WebSocket Protocol] Connected to OpenSSH {target_host}:{target_port} for {addr}")

        if initial_data:
            ssh_writer.write(initial_data)
            await ssh_writer.drain()

        await asyncio.gather(
            transfer_data(reader, ssh_writer, f"[WS->SSH] {addr}"),
            transfer_data(ssh_reader, writer, f"[SSH->WS] {addr}")
        )
    except ConnectionRefusedError:
        logger.error(f"[WebSocket Protocol] Connection refused to OpenSSH for {addr}")
    except Exception as e:
        logger.error(f"[WebSocket Protocol] Error during WebSocket for {addr}: {e}")
    finally:
        logger.info(f"[WebSocket Protocol] Closing connection for {addr}")
        writer.close()
        await writer.wait_closed()

async def dispatch_connection(reader, writer):
    addr = writer.get_extra_info("peername")
    local_port = writer.get_extra_info("sockname")[1]

    try:
        initial_data = await asyncio.wait_for(reader.read(4096), timeout=2)
        if b"GET / HTTP/1.1" in initial_data and b"upgrade: websocket" in initial_data.lower():
            logger.info(f"[Dispatcher] WebSocket upgrade detected from {addr}")
            response = b"HTTP/1.1 101 Proxy CloudJF\r\n\r\n"
            writer.write(response)
            await writer.drain()
            await handle_websocket_protocol(reader, writer, initial_data)
            return
        elif initial_data.startswith(b'\x05'):
            logger.info(f"[Dispatcher] SOCKS5 detected from {addr}")
            await handle_socks5_protocol(reader, writer, initial_data)
            return
        elif local_port in [443, 8443]:
            logger.info(f"[Dispatcher] Special port {local_port} treat as WebSocket for {addr}")
            response = b"HTTP/1.1 101 Proxy CloudJF\r\n\r\n"
            writer.write(response)
            await writer.drain()
            await handle_websocket_protocol(reader, writer, initial_data)
            return
        else:
            logger.warning(f"[Dispatcher] Unknown protocol from {addr}, data: {initial_data[:50]!r}")
            writer.close()
            await writer.wait_closed()
    except asyncio.TimeoutError:
        logger.warning(f"[Dispatcher] Timeout waiting for data from {addr}, closing")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        logger.error(f"[Dispatcher] Error dispatching connection from {addr}: {e}")
        writer.close()
        await writer.wait_closed()

async def start_socks5_proxy(port):
    try:
        server = await asyncio.start_server(dispatch_connection, '0.0.0.0', port)
        addr = server.sockets[0].getsockname()
        logger.info(f"[SOCKS5 Listener] Listening on {addr} (dispatch to SOCKS5 or WS)")
        async with server:
            await server.serve_forever()
    except Exception as e:
        logger.error(f"[SOCKS5 Listener] Failed to start server on port {port}: {e}")

async def start_websocket_proxy(port, use_wss=False, certfile=None, keyfile=None):
    try:
        if use_wss:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(certfile, keyfile)
            server = await asyncio.start_server(dispatch_connection, "0.0.0.0", port, ssl=ssl_context)
            logger.info(f"[WSS Listener] Listening on 0.0.0.0:{port} with SSL (dispatch to SOCKS5 or WS)")
        else:
            server = await asyncio.start_server(dispatch_connection, "0.0.0.0", port)
            logger.info(f"[WS Listener] Listening on 0.0.0.0:{port} (dispatch to SOCKS5 or WS)")
        async with server:
            await server.serve_forever()
    except Exception as e:
        logger.error(f"[WS/WSS Listener] Failed to start server on port {port}: {e}")

def generate_service_file(port, protocol, certfile=None, keyfile=None):
    service_name = f"proxyport@{port}.service"
    service_path = f"/etc/systemd/system/{service_name}"
    script_path = os.path.abspath(__file__)

    certfile_abs = os.path.abspath(certfile) if certfile else None
    keyfile_abs = os.path.abspath(keyfile) if keyfile else None

    if protocol == "WS":
        exec_start = f"/usr/bin/env python3 {script_path} --protocol ws --port {port}"
    elif protocol == "WSS":
        exec_start = f"/usr/bin/env python3 {script_path} --protocol wss --port {port}"
        if certfile_abs and keyfile_abs:
            exec_start += f" --certfile {certfile_abs} --keyfile {keyfile_abs}"
    elif protocol == "SOCKS5":
        exec_start = f"/usr/bin/env python3 {script_path} --protocol socks5 --port {port}"
    else:
        raise ValueError("Protocolo não suportado para geração de arquivo de serviço.")

    content = f"""[Unit]
Description=Proxy Service on Port {port} ({protocol})
After=network.target

[Service]
ExecStart={exec_start}
Restart=always
User=root
WorkingDirectory={os.path.dirname(script_path)}

[Install]
WantedBy=multi-user.target
"""
    return service_path, content

async def start_proxy_service(port, protocol, certfile=None, keyfile=None):
    if port in active_proxies:
        print(f"Erro: Porta {port} já está aberta pelo proxy.")
        return False

    if await is_port_in_use(port):
        print(f"Erro: Porta {port} já está sendo usada no sistema por outro processo.")
        return False

    service_path, content = generate_service_file(port, protocol, certfile, keyfile)
    service_name = os.path.basename(service_path)

    logger.info(f"Criando arquivo de serviço: {service_path}")
    proc_write = await asyncio.create_subprocess_shell(
        f"echo \"{content}\" | sudo tee {service_path}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout_write, stderr_write = await proc_write.communicate()
    if proc_write.returncode != 0:
        logger.error(f"Falha ao escrever arquivo de serviço: {stderr_write.decode().strip()}")
        return False

    logger.info(f"Habilitando e iniciando serviço: {service_name}")
    proc_start = await asyncio.create_subprocess_shell(
        f"sudo systemctl daemon-reload && sudo systemctl enable {service_name} && sudo systemctl restart {service_name}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc_start.communicate()
    if proc_start.returncode == 0:
        active_proxies[port] = {"protocol": protocol, "status": "running", "certfile": certfile, "keyfile": keyfile}
        await save_active_proxies()
        logger.info(f"Serviço {service_name} iniciado com sucesso.")
        print(f"Proxy aberto com sucesso na porta {port}.")
        return True
    else:
        logger.error(f"Falha ao iniciar serviço {service_name}: {stderr.decode().strip()}")
        print(f"Erro ao iniciar o serviço na porta {port}.")
        return False

async def stop_proxy_service(port):
    if port not in active_proxies:
        print(f"Erro: Porta {port} não está aberta pelo proxy.")
        return False

    service_name = f"proxyport@{port}.service"
    service_path = f"/etc/systemd/system/{service_name}"

    logger.info(f"Parando e desabilitando serviço: {service_name}")
    proc = await asyncio.create_subprocess_shell(
        f"sudo systemctl stop {service_name} && sudo systemctl disable {service_name} && sudo rm -f {service_path}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode == 0:
        logger.info(f"Serviço {service_name} parado e removido com sucesso.")
        del active_proxies[port]
        await save_active_proxies()
        print(f"Proxy fechado com sucesso na porta {port}.")
        return True
    else:
        logger.error(f"Falha ao parar o serviço {service_name}: {stderr.decode().strip()}")
        print(f"Erro ao fechar o proxy na porta {port}.")
        return False

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

async def show_menu():
    while True:
        clear_screen()
        print("="*50)
        print("         Proxy CloudJF v1.0 - Menu Principal")
        print("="*50)
        print("1. Abrir nova porta")
        print("2. Fechar porta")
        print("3. Listar portas abertas")
        print("4. Sair")
        print("="*50)
        choice = input("Digite sua escolha: ").strip()

        if choice == "1":
            await open_new_port_menu()
        elif choice == "2":
            await close_port_menu()
        elif choice == "3":
            await list_open_ports()
            input("\nPressione Enter para voltar ao menu...")
        elif choice == "4":
            logger.info("Saindo do menu. Os serviços em execução continuarão em segundo plano.")
            break
        else:
            print("Escolha inválida. Tente novamente.")
            input("Pressione Enter para continuar...")

async def open_new_port_menu():
    clear_screen()
    print("="*50)
    print("       Abrir nova porta no Proxy CloudJF")
    print("="*50)
    print("Escolha o protocolo:")
    print("1. WebSocket (WS)")
    print("2. WebSocket Secure (WSS)")
    print("3. SOCKS5")
    print("="*50)
    protocol_choice = input("Insira a escolha do protocolo: ").strip()

    try:
        port = int(input("Digite o número da porta: ").strip())
        if not (1 <= port <= 65535):
            raise ValueError("Número da porta deve estar entre 1 e 65535.")
    except ValueError as e:
        print(f"Número de porta inválido: {e}")
        input("Pressione Enter para voltar ao menu...")
        return

    certfile = None
    keyfile = None
    success = False

    if protocol_choice == "1":  # WS
        logger.info(f"Abrindo proxy WS na porta {port}...")
        success = await start_proxy_service(port, "WS")
    elif protocol_choice == "2":  # WSS
        cert_dir = "./network_proxy_server/certs"
        certfile = os.path.abspath(os.path.join(cert_dir, f"cert_{port}.pem"))
        keyfile = os.path.abspath(os.path.join(cert_dir, f"key_{port}.pem"))
        if not os.path.exists(certfile) or not os.path.exists(keyfile):
            logger.info(f"Certificado ou arquivo de chave não encontrado para a porta {port}. Gerando novos.")
            if not await generate_self_signed_cert(certfile, keyfile):
                logger.error("Falha ao gerar certificado e chave. Abortando proxy WSS.")
                input("Pressione Enter para voltar ao menu...")
                return
        else:
            logger.info(f"Usando certificado e chave existentes para porta {port}.")
        logger.info(f"Abrindo proxy WSS na porta {port}...")
        success = await start_proxy_service(port, "WSS", certfile=certfile, keyfile=keyfile)
    elif protocol_choice == "3":  # SOCKS5
        logger.info(f"Abrindo proxy SOCKS5 na porta {port}...")
        success = await start_proxy_service(port, "SOCKS5")
    else:
        print("Escolha de protocolo inválida.")
        input("Pressione Enter para voltar ao menu...")
        return

    if success:
        print(f"Proxy aberto com sucesso na porta {port}.")
    else:
        print(f"Falha ao abrir proxy na porta {port}.")
    input("Pressione Enter para voltar ao menu...")

async def close_port_menu():
    clear_screen()
    print("="*50)
    print("               Fechar porta")
    print("="*50)
    if not active_proxies:
        print("Nenhum proxy ativo para fechar.")
        input("Pressione Enter para voltar ao menu...")
        return

    print("Proxies ativos:")
    for port, details in active_proxies.items():
        print(f"  Porta: {port}, Protocolo: {details['protocol']}")

    try:
        port_to_close = int(input("Digite o número da porta para fechar: ").strip())
        if port_to_close not in active_proxies:
            print("Porta não encontrada em proxies ativos.")
            input("Pressione Enter para voltar ao menu...")
            return

        await stop_proxy_service(port_to_close)
    except ValueError:
        print("Número de porta inválido.")

    input("Pressione Enter para voltar ao menu...")

async def list_open_ports():
    clear_screen()
    print("="*50)
    print("         Status de portas abertas")
    print("="*50)
    if not active_proxies:
        print("Nenhum proxy é gerenciado atualmente por esta sessão.")
        print("Nota: mostra apenas proxies criados por este menu (sessão atual).")
        print("Para status completo, verifique: sudo systemctl list-units --type=service | grep proxyport")
        return

    print("Proxies gerenciados nesta sessão:")
    for port, details in active_proxies.items():
        print(f"  Porta: {port}, Protocolo: {details['protocol']}, Status: {details['status']}")

async def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--protocol":
        protocol = sys.argv[2]
        try:
            port = int(sys.argv[4])
        except Exception:
            logger.error("Argumento de porta inválido.")
            sys.exit(1)
        certfile = None
        keyfile = None
        if "--certfile" in sys.argv:
            try:
                certfile = sys.argv[sys.argv.index("--certfile")+1]
            except IndexError:
                logger.error("Argumento --certfile sem valor.")
                sys.exit(1)
        if "--keyfile" in sys.argv:
            try:
                keyfile = sys.argv[sys.argv.index("--keyfile")+1]
            except IndexError:
                logger.error("Argumento --keyfile sem valor.")
                sys.exit(1)

        setup_logging(log_to_file=True)

        if protocol in ("WS", "WSS"):
            await start_websocket_proxy(port, use_wss=(protocol=="WSS"), certfile=certfile, keyfile=keyfile)
        elif protocol == "SOCKS5":
            await start_socks5_proxy(port)
        else:
            logger.error(f"Protocolo desconhecido: {protocol}")
            sys.exit(1)
    else:
        setup_logging()
        logger.info("Network Proxy Server - Inicializando...")
        await load_active_proxies()
        await show_menu()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nNetwork Proxy Server - Encerrando.")
    except Exception as e:
        logger.critical(f"Erro não tratado: {e}", exc_info=True)
        sys.exit(1)

