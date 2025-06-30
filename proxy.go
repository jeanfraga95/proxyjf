package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
)
const (
	logFilePath = "/var/log/proxyws.log"
	pidFileDir  = "/var/run"
	serviceDir  = "/etc/systemd/system"
	readTimeout = time.Second * 3
)

var (
	logMutex  sync.Mutex
	sslConfig *tls.Config
	stopChan  chan struct{}
)

func logMessage(msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Erro ao escrever no log: %v\n", err)
		return
	}
	defer f.Close()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(f, "[%s] %s\n", timestamp, msg)
}

func detectProtocol(data []byte) string {
	if len(data) == 0 {
		return "unknown"
	}

	dataStr := strings.ToLower(string(data))

	// Detect SOCKS5
	if len(data) >= 3 && data[0] == 0x05 {
		return "socks5"
	}

	// Detect SOCKS4
	if len(data) >= 8 && data[0] == 0x04 {
		return "socks4"
	}

	// Detect WebSocket
	if (strings.HasPrefix(dataStr, "get ") ||
		strings.HasPrefix(dataStr, "post ") ||
		strings.HasPrefix(dataStr, "put ") ||
		strings.HasPrefix(dataStr, "delete ") ||
		strings.HasPrefix(dataStr, "options ") ||
		strings.HasPrefix(dataStr, "head ") ||
		strings.HasPrefix(dataStr, "connect ") ||
		strings.HasPrefix(dataStr, "patch ") ||
		strings.HasPrefix(dataStr, "trace ") ||
		strings.HasPrefix(dataStr, "propfind ") ||
		strings.HasPrefix(dataStr, "proppatch ") ||
		strings.HasPrefix(dataStr, "mkcol ") ||
		strings.HasPrefix(dataStr, "copy ") ||
		strings.HasPrefix(dataStr, "move ") ||
		strings.HasPrefix(dataStr, "lock ") ||
		strings.HasPrefix(dataStr, "unlock ")) &&
		(strings.Contains(dataStr, "upgrade: websocket") ||
			strings.Contains(dataStr, "connection: upgrade") ||
			strings.Contains(dataStr, "connection: websocket")) {
		return "websocket"
	}

	// Detect HTTP
	if strings.HasPrefix(dataStr, "get ") || 
	   strings.HasPrefix(dataStr, "post ") ||
	   strings.HasPrefix(dataStr, "put ") ||
	   strings.HasPrefix(dataStr, "delete ") ||
	   strings.HasPrefix(dataStr, "options ") ||
	   strings.HasPrefix(dataStr, "head ") ||
	   strings.HasPrefix(dataStr, "patch ") ||
	   strings.HasPrefix(dataStr, "trace ") ||
	   strings.HasPrefix(dataStr, "propfind ") ||
	   strings.HasPrefix(dataStr, "proppatch ") ||
	   strings.HasPrefix(dataStr, "mkcol ") ||
	   strings.HasPrefix(dataStr, "copy ") ||
	   strings.HasPrefix(dataStr, "move ") ||
	   strings.HasPrefix(dataStr, "lock ") ||
	   strings.HasPrefix(dataStr, "unlock ") ||
	   strings.HasPrefix(dataStr, "search ") {
		return "http"
	}

	// Detect HTTP CONNECT
	if strings.HasPrefix(dataStr, "connect ") {
		return "http_connect"
	}

	return "websocket"
}

func handleConnection(conn net.Conn) {
	// Use the buffered connection to read initial data
	bufConn, ok := conn.(*bufferedConn)
	if !ok {
		logMessage("Erro: conexão não é do tipo bufferedConn")
		conn.Close()
		return
	}

	// Read initial data from the buffered connection
	initialData, err := bufConn.Peek(bufConn.Reader.Buffered())
	if err != nil && err != io.EOF {
		logMessage(fmt.Sprintf("Erro ao espiar dados iniciais: %v", err))
		conn.Close()
		return
	}

	protocol := detectProtocol(initialData)
	logMessage(fmt.Sprintf("Protocolo detectado: %s", protocol))

	var resp string
	switch protocol {
	case "socks5", "socks4":
		resp = "HTTP/1.1 200 OK\r\n\r\n"
		logMessage("Conexão SOCKS estabelecida")

	case "websocket":
		resp = "HTTP/1.1 101 Proxy CLOUDJF\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		logMessage("Conexão WebSocket estabelecida")

	case "http_connect":
		// For HTTP CONNECT, we don't send an immediate response here.
		// The sshRedirect will handle the CONNECT handshake.
		logMessage("Conexão HTTP CONNECT detectada")
		resp = ""

	case "http":
		// For plain HTTP, we also don't send an immediate response here.
		// The sshRedirect will handle the HTTP request.
		logMessage("Conexão HTTP detectada")
		resp = ""

	default:
		resp = "HTTP/1.1 101 Proxy CLOUDJF\r\n\r\n"
		logMessage("Conexão TCP estabelecida")
	}

	// Envia resposta, se aplicável
	if resp != "" {
		if _, err := conn.Write([]byte(resp)); err != nil {
			logMessage("Erro enviando resposta: " + err.Error())
			conn.Close()
			return
		}
	}
	sshRedirect(conn, initialData, protocol)
}

func sshRedirect(conn net.Conn, initialData []byte, protocol string) {
	var targetConn net.Conn
	var targetAddr string
	var err error // Declare err here

	if protocol == "http_connect" {
		// Parse the CONNECT request to get the target address
		reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
		req, errReq := http.ReadRequest(reader)
		if errReq != nil {
			logMessage(fmt.Sprintf("Erro lendo requisição CONNECT: %v", errReq))
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		targetAddr = req.Host
		logMessage(fmt.Sprintf("CONNECT para: %s", targetAddr))

		targetConn, err = net.Dial("tcp", targetAddr)
		if err != nil {
			logMessage(fmt.Sprintf("Erro conectando ao destino CONNECT %s: %v", targetAddr, err))
			conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
			return
		}
		// Send 200 OK to the client for CONNECT
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	} else if protocol == "http" {
		// For plain HTTP, forward to SSH server
		targetAddr = "127.0.0.1:22"
		targetConn, err = net.Dial("tcp", targetAddr)
		if err != nil {
			logMessage(fmt.Sprintf("Erro conectando servidor SSH para HTTP: %v", err))
			return
		}
		// Write initial HTTP data to the SSH server
		if _, err = targetConn.Write(initialData); err != nil {
			logMessage(fmt.Sprintf("Erro enviando dados HTTP iniciais para SSH: %v", err))
			return
		}
	} else {
		// For other protocols (SOCKS, WebSocket, TCP), connect to SSH
		targetAddr = "127.0.0.1:22"
		targetConn, err = net.Dial("tcp", targetAddr)
		if err != nil {
			logMessage(fmt.Sprintf("Erro conectando servidor SSH: %v", err))
			return
		}
		if initialData != nil && len(initialData) > 0 {
			if _, err = targetConn.Write(initialData); err != nil {
				logMessage(fmt.Sprintf("Erro enviando dados iniciais para SSH: %v", err))
				return
			}
		}
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
	}()

	wg.Wait()
	logMessage(fmt.Sprintf("Conexão %s finalizada", protocol))
}

func systemdServicePath(port int) string {
	return fmt.Sprintf("%s/proxyws@%d.service", serviceDir, port)
}

func createSystemdService(port int, execPath string) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=ProxyWS Multiprotocolo na porta %d
After=network.target

[Service]
Type=simple
ExecStart=%s %d
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
`, port, execPath, port)
	path := systemdServicePath(port)
	return os.WriteFile(path, []byte(serviceContent), 0644)
}

func enableAndStartService(port int) error {
	serviceName := fmt.Sprintf("proxyws@%d.service", port)
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("systemctl", "enable", serviceName)
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("systemctl", "start", serviceName)
	return cmd.Run()
}

func stopAndDisableService(port int) error {
	serviceName := fmt.Sprintf("proxyws@%d.service", port)
	serviceFile := fmt.Sprintf("/etc/systemd/system/%s", serviceName)

	// 1. Parar o serviço
	if err := exec.Command("systemctl", "stop", serviceName).Run(); err != nil {
		return fmt.Errorf("falha ao parar o serviço %s: %w", serviceName, err)
	}
	fmt.Printf("✅ Serviço %s parado com sucesso.\n", serviceName)

	// 2. Desabilitar o serviço
	if err := exec.Command("systemctl", "disable", serviceName).Run(); err != nil {
		return fmt.Errorf("falha ao desabilitar o serviço %s: %w", serviceName, err)
	}
	fmt.Printf("✅ Serviço %s desabilitado com sucesso.\n", serviceName)

	// 3. Remover o arquivo do serviço
	if err := os.Remove(serviceFile); err != nil {
		return fmt.Errorf("falha ao remover o arquivo do serviço %s: %w", serviceFile, err)
	}
	fmt.Printf("🗑️ Arquivo do serviço %s removido com sucesso.\n", serviceFile)

	// 4. Recarregar o systemd para aplicar as mudanças
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("falha ao recarregar o systemd: %w", err)
	}
	fmt.Println("🔄 systemd recarregado com sucesso.")

	return nil

}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func printHeader() {
	clearScreen()
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║        🚀 PROXY CloudJF v2.1 🚀     ║")
	fmt.Println("║      Multiprotocolo SSH Proxy        ║")
	fmt.Println("╠══════════════════════════════════════╣")
	fmt.Println("║  Suporta: WebSocket, SOCKS4-5        ║")
	fmt.Println("║                                     )║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println()
}

func printMenu() {
	fmt.Println("┌─────────────────────────────────────┐")
	fmt.Println("│              📋 MENU                │")
	fmt.Println("├─────────────────────────────────────┤")
	fmt.Println("│  1️⃣  - Abrir nova porta             │")
	fmt.Println("│  2️⃣  - Fechar porta                 │")
	fmt.Println("│  3️⃣  - Listar portas ativas         │")
	fmt.Println("│  4️⃣  - Status do sistema            │")
	fmt.Println("│  5️⃣  - Ver logs                     │")
	fmt.Println("│  0️⃣  - Sair                         │")
	fmt.Println("└─────────────────────────────────────┘")
	fmt.Print("\n🔸 Escolha uma opção: ")
}

func listActivePorts() {
	clearScreen()
	printHeader()
	fmt.Println("📊 PORTAS ATIVAS:")
	fmt.Println("═══════════════════")

	cmd := exec.Command("systemctl", "list-units", "--type=service", "--state=active", "proxyws@*")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("❌ Erro ao listar serviços ativos")
		return
	}

	if len(output) == 0 {
		fmt.Println("ℹ️  Nenhuma porta ativa encontrada")
	} else {
		fmt.Println(string(output))
	}

	fmt.Print("\n📌 Pressione Enter para continuar...")
}

func showSystemStatus() {
	clearScreen()
	printHeader()
	fmt.Println("🖥️  STATUS DO SISTEMA:")
	fmt.Println("═══════════════════════")

	cmd := exec.Command("systemctl", "is-active", "ssh")
	output, _ := cmd.Output()
	sshStatus := strings.TrimSpace(string(output))

	if sshStatus == "active" {
		fmt.Println("✅ OpenSSH: Ativo")
	} else {
		fmt.Println("❌ OpenSSH: Inativo")
	}

	cmd = exec.Command("ss", "-tlnp")
	output, err := cmd.Output()
	if err == nil {
		fmt.Println("\n🔌 Portas em uso:")
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, ":22 ") {
				fmt.Println("   📍 SSH (22): Ativo")
				break
			}
		}
	}

	fmt.Print("\n📌 Pressione Enter para continuar...")
}

func showLogs() {
	clearScreen()
	printHeader()
	fmt.Println("📜 ÚLTIMOS LOGS:")
	fmt.Println("═══════════════════")

	cmd := exec.Command("tail", "-20", logFilePath)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("❌ Erro ao ler logs ou arquivo não existe")
	} else {
		fmt.Println(string(output))
	}

	fmt.Print("\n📌 Pressione Enter para continuar...")
}

func waitForEnter() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
}

func startProxy(port int) {
	addr := fmt.Sprintf(":%d", port)
	
	// Create a regular TCP listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logMessage(fmt.Sprintf("Erro iniciando listener TCP na porta %d: %v", port, err))
		return
	}
	defer listener.Close()

	logMessage(fmt.Sprintf("Proxy multiprotocolo iniciado na porta %d (TCP)", port))

	pidFile := fmt.Sprintf("%s/proxyws_%d.pid", pidFileDir, port)
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		logMessage(fmt.Sprintf("Falha ao gravar PID file: %v", err))
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			sig := <-sigCh
			logMessage(fmt.Sprintf("Sinal %v recebido, mantendo proxy ativo", sig))
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				logMessage(fmt.Sprintf("Erro temporário na porta %d: %v", port, err))
				time.Sleep(50 * time.Millisecond)
				continue
			}
			logMessage(fmt.Sprintf("Erro fatal na porta %d: %v", port, err))
			break
		}

		// Check if the connection is TLS
		var clientConn net.Conn
		peekedBytes := make([]byte, 5)
		n, err := conn.Read(peekedBytes)
		if err != nil {
			logMessage(fmt.Sprintf("Erro ao ler bytes iniciais: %v", err))
			conn.Close()
			continue
		}

		isTLS := false
		if n >= 1 && peekedBytes[0] == 0x16 { // TLS Handshake record type
			isTLS = true
		}

		if isTLS && sslConfig != nil {
			// Wrap the connection in a TLS server
			tlsConn := tls.Server(conn, sslConfig)
			err = tlsConn.Handshake()
			if err != nil {
				logMessage(fmt.Sprintf("Erro no handshake TLS: %v", err))
				tlsConn.Close()
				continue
			}
			clientConn = tlsConn
			logMessage("Conexão TLS detectada e handshake bem-sucedido")
			// Prepend the peeked bytes to the TLS connection
			clientConn = &bufferedConn{Reader: bufio.NewReader(io.MultiReader(bytes.NewReader(peekedBytes[:n]), tlsConn)), Conn: tlsConn}
		} else {
			clientConn = &bufferedConn{Reader: bufio.NewReader(io.MultiReader(bytes.NewReader(peekedBytes[:n]), conn)), Conn: conn}
			logMessage("Conexão TCP/HTTP detectada")
		}

		go handleConnection(clientConn)
	}

	logMessage(fmt.Sprintf("Proxy encerrado na porta %d", port))
	os.Remove(pidFile)
}

// bufferedConn wraps a net.Conn and a bufio.Reader to allow peeking bytes
type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (n int, err error) {
	return b.Reader.Read(p)
}

func (b *bufferedConn) Close() error {
	return b.Conn.Close()
}
	func main() {
	if len(os.Args) > 1 {
		port, err := strconv.Atoi(os.Args[1])
		if err != nil {
			fmt.Printf("❌ Parâmetro inválido: %s\n", os.Args[1])
			return
		}

		certPath := "/opt/proxyapp/cert.pem"
		keyPath := "/opt/proxyapp/key.pem"

		_, errCert := os.Stat(certPath)
		_, errKey := os.Stat(keyPath)

		if os.IsNotExist(errCert) || os.IsNotExist(errKey) {
			fmt.Println("📢 Certificados não encontrados. Tentando gerar...")
			if err := generateSelfSignedCert(certPath, keyPath); err != nil {
				fmt.Println("❌ Erro ao gerar certificados:", err)
			} else {
				fmt.Println("✅ Certificados gerados com sucesso.")
			}
		} else {
			fmt.Println("✅ Certificados já existem. Pulando geração.")
		}

		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			sslConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			logMessage("✅ Certificados TLS carregados com sucesso")
		} else {
			logMessage("⚠️  Erro ao carregar certificados TLS: " + err.Error())
		}

		stopChan = make(chan struct{})
		startProxy(port)
		return
	}
	

	execPath, _ := os.Executable()
	scanner := bufio.NewScanner(os.Stdin)

	for {
		printHeader()
		printMenu()

		if !scanner.Scan() {
			break
		}
		option := strings.TrimSpace(scanner.Text())

		switch option {
		case "1":
			clearScreen()
			printHeader()
			fmt.Println("🔧 ABRIR NOVA PORTA")
			fmt.Println("═══════════════════")
			fmt.Print("🔸 Digite a porta (1-65535): ")

			if !scanner.Scan() {
				break
			}
			portStr := strings.TrimSpace(scanner.Text())
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				clearScreen()
				printHeader()
				fmt.Println("❌ Porta inválida!")
				fmt.Print("📌 Pressione Enter para continuar...")
				waitForEnter()
				continue
			}

			clearScreen()
			printHeader()
			fmt.Printf("⚙️  Configurando porta %d...\n", port)

			if err := createSystemdService(port, execPath); err != nil {
				fmt.Printf("❌ Erro criando service: %v\n", err)
				fmt.Print("📌 Pressione Enter para continuar...")
				waitForEnter()
				continue
			}

			if err := enableAndStartService(port); err != nil {
				fmt.Printf("❌ Erro iniciando service: %v\n", err)
				fmt.Print("📌 Pressione Enter para continuar...")
				waitForEnter()
				continue
			}

			fmt.Printf("✅ Proxy multiprotocolo iniciado na porta %d\n", port)
			fmt.Println("🔹 Protocolos suportados: WebSocket, SOCKS4/5")
			fmt.Println("🔹 Não Funciona com OpenVPN")
			fmt.Print("📌 Pressione Enter para continuar...")
			waitForEnter()

		case "2":
	clearScreen()
	printHeader()
	fmt.Println("🔧 FECHAR PORTA")
	fmt.Println("═══════════════")
	fmt.Print("🔸 Digite a porta a ser fechada: ")

	if !scanner.Scan() {
		break
	}
	portStr := strings.TrimSpace(scanner.Text())
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		clearScreen()
		printHeader()
		fmt.Println("❌ Porta inválida!")
		fmt.Print("📌 Pressione Enter para continuar...")
		waitForEnter()
		continue
	}

	clearScreen()
	printHeader()
	fmt.Printf("⚠️  Tem certeza que deseja fechar a porta %d? (s/N): ", port)

	if !scanner.Scan() {
		break
	}
	conf := strings.ToLower(strings.TrimSpace(scanner.Text()))

	if conf == "s" || conf == "sim" {
		fmt.Println("⏳ Encerrando porta, aguarde...")

		start := time.Now()
		err := stopAndDisableService(port)
		elapsed := time.Since(start)
		logMessage(fmt.Sprintf("Tempo para encerrar porta %d: %v", port, elapsed))

		if err != nil {
			fmt.Printf("❌ Erro ao parar service: %v\n", err)
		} else {
			fmt.Printf("✅ Porta %d encerrada com sucesso\n", port)
		}
	} else {
		fmt.Println("❌ Operação cancelada")
	}

	fmt.Print("📌 Pressione Enter para continuar...")
	waitForEnter()


		case "3":
			listActivePorts()
			waitForEnter()

		case "4":
			showSystemStatus()
			waitForEnter()

		case "5":
			showLogs()
			waitForEnter()

		case "0":
			clearScreen()
			printHeader()
			fmt.Println("👋 Saindo do menu...")
			fmt.Println("ℹ️  Os proxies ativos continuam em execução")
			fmt.Println("🔹 Use 'systemctl status proxyws@PORTA' para verificar status")
			return

		default:
			clearScreen()
			printHeader()
			fmt.Println("❌ Opção inválida!")
			fmt.Print("📌 Pressione Enter para continuar...")
			waitForEnter()
		}
	}
}
func generateSelfSignedCert(certFile, keyFile string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("erro ao obter hostname: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"AutoGenerated Cert"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}

	return nil
}
