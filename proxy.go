package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
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

// detectProtocol is no longer used in the same way as before, as the Rust logic is different.
// We'll keep it for now but its role in handleConnection will change.
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

	// Detect WebSocket (or any non-SOCKS connection)
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
		strings.HasPrefix(dataStr, "copy ") ||		strings.HasPrefix(dataStr, "move ") ||
		strings.HasPrefix(dataStr, "lock ") ||
		strings.HasPrefix(dataStr, "unlock ") ||
		strings.HasPrefix(dataStr, "search ") ||
		strings.Contains(dataStr, "upgrade: websocket") ||
		strings.Contains(dataStr, "connection: upgrade") ||
		strings.Contains(dataStr, "connection: websocket")) {
		return "websocket"
	}

	return "websocket"
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Rust proxy sends 101 immediately
	status := "@RustyManager" // This can be made configurable if needed
	resp101 := fmt.Sprintf("HTTP/1.1 101 %s\r\n\r\n", status)
	if _, err := conn.Write([]byte(resp101)); err != nil {
		logMessage("Erro enviando resposta 101: " + err.Error())
		return
	}
	logMessage("Enviado HTTP/1.1 101")

	// Rust proxy reads some initial data and then sends 200
	buffer := make([]byte, 1024)
	_, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		logMessage(fmt.Sprintf("Erro ao ler dados iniciais após 101: %v", err))
		return
	}

	resp200 := fmt.Sprintf("HTTP/1.1 200 %s\r\n\r\n", status)
	if _, err := conn.Write([]byte(resp200)); err != nil {
		logMessage("Erro enviando resposta 200: " + err.Error())
		return
	}
	logMessage("Enviado HTTP/1.1 200")

	// Peek into the stream to decide target address
	// In Go, we can't easily 'peek' from a net.Conn like Rust's TcpStream.peek().
	// The original Go code already reads initial bytes into peekedBytes.
	// We'll use that for protocol detection, similar to Rust's peek_stream logic.
	
	// The original Go code already has peekedBytes from startProxy. We need to pass it.
	// For now, let's assume the initial read into 'buffer' above serves this purpose
	// and adapt the logic to use 'buffer' for protocol detection.

	var targetAddr string
	// Simulate Rust's peek_stream logic
	dataStr := strings.ToUpper(string(buffer))

	if strings.Contains(dataStr, "SSH") || strings.TrimSpace(dataStr) == "" {
		targetAddr = "127.0.0.1:22"
		logMessage("Detectado SSH ou vazio, redirecionando para 127.0.0.1:22")
	} else {
		targetAddr = "127.0.0.1:1194"
		logMessage("Detectado não-SSH, redirecionando para 127.0.0.1:1194")
	}

	// Connect to the target server
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		logMessage(fmt.Sprintf("Erro conectando ao servidor de destino %s: %v", targetAddr, err))
		return
	}
	defer targetConn.Close()

	// Write the initial buffered data to the target server
	if _, err := targetConn.Write(buffer); err != nil {
		logMessage(fmt.Sprintf("Erro enviando dados iniciais para o servidor de destino: %v", err))
		return
	}

	// Bidirectional data transfer
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		// Read from the client connection and write to the target server connection
		if _, err := io.Copy(targetConn, conn); err != nil {
			logMessage(fmt.Sprintf("Erro ao copiar dados do cliente para o servidor de destino: %v", err))
		}
	}()

	go func() {
		defer wg.Done()
		// Read from the target server connection and write back to the client connection
		if _, err := io.Copy(conn, targetConn); err != nil {
			logMessage(fmt.Sprintf("Erro ao copiar dados do servidor de destino para o cliente: %v", err))
		}
	}()

	wg.Wait()
	logMessage(fmt.Sprintf("Conexão finalizada com %s", targetAddr))
}

func systemdServicePath(port int) string {
	return fmt.Sprintf("%s/proxyws@%d.service", serviceDir, port)
}

func createSystemdService(port int, execPath string) error {
	serviceContent := fmt.Sprintf(`[Unit]\nDescription=ProxyWS Multiprotocolo na porta %d\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=%s %d\nRestart=always\nRestartSec=5\nUser=root\n\n[Install]\nWantedBy=multi-user.target\n`, execPath, port)
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

		// In the Go version, we're not using bufferedConn and peekedBytes in the same way
		// as the previous Go code. The Rust logic sends 101, then reads, then 200,
		// then peeks (which is simulated by the read into 'buffer' in handleConnection).
		// So, we directly pass the accepted connection to handleConnection.
		go handleConnection(conn)
	}

	logMessage(fmt.Sprintf("Proxy encerrado na porta %d", port))
	os.Remove(pidFile)
}

// bufferedConn and related logic is removed as it's not directly applicable
// to the Rust proxy's behavior of sending 101, reading, then 200.
// The initial read in handleConnection will serve the purpose of consuming
// the initial client data.

func generateSelfSignedCert(certPath, keyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("falha ao gerar chave privada: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"CloudJF Proxy"},
			CommonName:   "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // Validade de 1 ano

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("falha ao criar certificado: %w", err)
	}

	// Salvar certificado
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("falha ao abrir %s para escrita: %w", certPath, err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("falha ao escrever dados no %s: %w", certPath, err)
	}

	// Salvar chave privada
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("falha ao abrir %s para escrita: %w", keyPath, err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return fmt.Errorf("falha ao escrever dados no %s: %w", keyPath, err)
	}

	return nil
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
		fmt.Println("❌ Operação cancelada.")
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
			fmt.Println("👋 Saindo...")
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


