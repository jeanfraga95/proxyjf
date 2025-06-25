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
                log.Printf("Erro ao escrever no log: %v\n", err) // Corrigido: \n explícito
                return
        }
        defer f.Close()
        timestamp := time.Now().Format("2006-01-02 15:04:05")
        fmt.Fprintf(f, "[%s] %s\n", timestamp, msg) // Corrigido: \n explícito
}

// Detecta o tipo de protocolo baseado nos dados iniciais
func detectProtocol(data []byte) string {
        if len(data) == 0 {
                return "unknown"
        }

        dataStr := strings.ToLower(string(data))

        // Detecta SOCKS5
        if len(data) >= 3 && data[0] == 0x05 {
                return "socks5"
        }

        // Detecta SOCKS4
        if len(data) >= 8 && data[0] == 0x04 {
                return "socks4"
        }

        // Detecta WebSocket
        if (
        strings.HasPrefix(dataStr, "GET ") ||
        strings.HasPrefix(dataStr, "POST ") ||
        strings.HasPrefix(dataStr, "PUT ") ||
        strings.HasPrefix(dataStr, "DELETE ") ||
        strings.HasPrefix(dataStr, "OPTIONS ") ||
        strings.HasPrefix(dataStr, "HEAD ") ||
        strings.HasPrefix(dataStr, "CONNECT ") ||
        strings.HasPrefix(dataStr, "PATCH ") ||
        strings.HasPrefix(dataStr, "TRACE ") ||
        strings.HasPrefix(dataStr, "PROPFIND ") ||
        strings.HasPrefix(dataStr, "PROPPATCH ") ||
        strings.HasPrefix(dataStr, "MKCOL ") ||
        strings.HasPrefix(dataStr, "COPY ") ||
        strings.HasPrefix(dataStr, "MOVE ") ||
        strings.HasPrefix(dataStr, "LOCK ") ||
        strings.HasPrefix(dataStr, "UNLOCK ") ||
if (strings.HasPrefix(dataStr, "GET ") ||
    strings.HasPrefix(dataStr, "POST ") ||
    strings.HasPrefix(dataStr, "PUT ") ||
    strings.HasPrefix(dataStr, "DELETE ") ||
    strings.HasPrefix(dataStr, "OPTIONS ") ||
    strings.HasPrefix(dataStr, "HEAD ") ||
    strings.HasPrefix(dataStr, "CONNECT ") ||
    strings.HasPrefix(dataStr, "PATCH ") ||
    strings.HasPrefix(dataStr, "PROPFIND ") ||
    strings.HasPrefix(dataStr, "UNLOCK ") ||
    strings.HasPrefix(dataStr, "SEARCH ")) &&
   (strings.Contains(dataStrLower, "upgrade: websocket") ||
    strings.Contains(dataStrLower, "connection: keep-alive") ||
    strings.Contains(dataStrLower, "connection: websocket")) {
    return "websocket"
}
}

}

        // Detecta HTTP/HTTPS
        if strings.HasPrefix(dataStr, "GET ") || 
   strings.HasPrefix(dataStr, "POST ") ||
   strings.HasPrefix(dataStr, "PUT ") ||
   strings.HasPrefix(dataStr, "DELETE ") ||
   strings.HasPrefix(dataStr, "OPTIONS ") ||
   strings.HasPrefix(dataStr, "HEAD ") ||
   strings.HasPrefix(dataStr, "CONNECT ") ||
   strings.HasPrefix(dataStr, "PATCH ") ||
   strings.HasPrefix(dataStr, "TRACE ") ||
   strings.HasPrefix(dataStr, "PROPFIND ") ||
   strings.HasPrefix(dataStr, "PROPPATCH ") ||
   strings.HasPrefix(dataStr, "MKCOL ") ||
   strings.HasPrefix(dataStr, "COPY ") ||
   strings.HasPrefix(dataStr, "MOVE ") ||
   strings.HasPrefix(dataStr, "LOCK ") ||
   strings.HasPrefix(dataStr, "UNLOCK ") ||
   strings.HasPrefix(dataStr, "SEARCH ") {
    return "websocket"
}

return "websocket"

// Função principal para lidar com conexões multiprotocolo
func handleConnection(conn net.Conn) {
        defer conn.Close()

        // Lê dados iniciais com timeout
        buf := make([]byte, 8192)
        conn.SetReadDeadline(time.Now().Add(readTimeout))
        n, err := conn.Read(buf)
        if err != nil {
                logMessage(fmt.Sprintf("Erro leitura inicial: %v", err))
                // Mesmo com erro, tenta redirecionar como TCP simples
                sshRedirect(conn, nil, "tcp")
                return
        }
        conn.SetReadDeadline(time.Time{}) // Remove timeout

        initialData := buf[:n]
        protocol := detectProtocol(initialData)

        logMessage(fmt.Sprintf("Protocolo detectado: %s", protocol))

        var resp string

        switch protocol {
        case "socks5", "socks4":
                // Resposta específica para SOCKS
                resp = "HTTP/1.1 200 OK\r\n\r\n" // Corrigido: \r\n explícito
                logMessage("Conexão SOCKS estabelecida")

        case "websocket":
                // Resposta para WebSocket Security
                resp = "HTTP/1.1 101 Proxy CLOUDJF\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" // Corrigido: \r\n explícito
                logMessage("Conexão WebSocket Security estabelecida")

        case "http":
                // Resposta para HTTP/HTTPS
                resp = "HTTP/1.1 101 Proxy CLOUDJF\r\n\r\n" // Corrigido: \r\n explícito
                logMessage("Conexão HTTP estabelecida")

        default:
                // TCP simples
                resp = "HTTP/1.1 101 Proxy CLOUDJF\r\n\r\n" // Corrigido: \r\n explícito
                logMessage("Conexão TCP estabelecida")
        }

        // Envia resposta apropriada
        if _, err := conn.Write([]byte(resp)); err != nil {
                logMessage("Erro enviando resposta: " + err.Error())
                return
        }

        // Redireciona para SSH
        sshRedirect(conn, initialData, protocol)
}

// Redireciona a conexão para servidor SSH
func sshRedirect(conn net.Conn, initialData []byte, protocol string) {
        serverConn, err := net.Dial("tcp", "127.0.0.1:22")
        if err != nil {
                logMessage(fmt.Sprintf("Erro conectando servidor SSH: %v", err))
                return
        }
        defer serverConn.Close()

        // Para protocolos que precisam dos dados iniciais no SSH
        if protocol == "tcp" && initialData != nil && len(initialData) > 0 {
                if _, err := serverConn.Write(initialData); err != nil {
                        logMessage(fmt.Sprintf("Erro enviando dados iniciais para SSH: %v", err))
                        return
                }
        }

        var wg sync.WaitGroup
        wg.Add(2)

        // Cliente -> Servidor SSH
        go func() {
                defer wg.Done()
                io.Copy(serverConn, conn)
        }()

        // Servidor SSH -> Cliente
        go func() {
                defer wg.Done()
                io.Copy(conn, serverConn)
        }()

        wg.Wait()
        logMessage(fmt.Sprintf("Conexão %s finalizada", protocol))
}

// Systemd service path
func systemdServicePath(port int) string {
        return fmt.Sprintf("%s/proxyws@%d.service", serviceDir, port)
}

// Cria arquivo de service systemd
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

        // Parar o serviço
        if err := exec.Command("systemctl", "stop", serviceName).Run(); err != nil {
                return fmt.Errorf("falha ao parar o serviço %s: %w", serviceName, err)
        }
        fmt.Printf("✅ Serviço %s parado com sucesso.\n", serviceName)

        // Desabilitar o serviço
        if err := exec.Command("systemctl", "disable", serviceName).Run(); err != nil {
                return fmt.Errorf("falha ao desabilitar o serviço %s: %w", serviceName, err)
        }
        fmt.Printf("✅ Serviço %s desabilitado com sucesso.\n", serviceName)

        // Remover o arquivo do serviço
        if err := os.Remove(systemdServicePath(port)); err != nil {
                return fmt.Errorf("falha ao remover o arquivo do serviço: %w", err)
        }
        fmt.Printf("🗑️ Arquivo do serviço %s removido com sucesso.\n", serviceName)

        return nil
}


func clearScreen() {
        fmt.Print("\033[H\033[2J")
}

func printHeader() {
        clearScreen()
        fmt.Println("╔══════════════════════════════════════╗")
        fmt.Println("║        🚀 PROXY CloudJF v2.1 🚀        ║")
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
        fmt.Print("\n🔸 Escolha uma opção: ") // Corrigido: \n explícito
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

        fmt.Print("\n📌 Pressione Enter para continuar...") // Corrigido: \n explícito
}

func showSystemStatus() {
        clearScreen()
        printHeader()
        fmt.Println("🖥️  STATUS DO SISTEMA:")
        fmt.Println("═══════════════════════")

        // Verifica se SSH está rodando
        cmd := exec.Command("systemctl", "is-active", "ssh")
        output, _ := cmd.Output()
        sshStatus := strings.TrimSpace(string(output))

        if sshStatus == "active" {
                fmt.Println("✅ OpenSSH: Ativo")
        } else {
                fmt.Println("❌ OpenSSH: Inativo")
        }

        // Verifica portas em uso
        cmd = exec.Command("ss", "-tlnp")
        output, err := cmd.Output()
        if err == nil {
                fmt.Println("\n🔌 Portas em uso:") // Corrigido: \n explícito
                lines := strings.Split(string(output), "\n") // Corrigido: \n explícito
                for _, line := range lines {
                        if strings.Contains(line, ":22 ") {
                                fmt.Println("   📍 SSH (22): Ativo")
                                break
                        }
                }
        }

        fmt.Print("\n📌 Pressione Enter para continuar...") // Corrigido: \n explícito
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

        fmt.Print("\n📌 Pressione Enter para continuar...") // Corrigido: \n explícito
}

func waitForEnter() {
        scanner := bufio.NewScanner(os.Stdin)
        scanner.Scan()
}

func main() {
        if len(os.Args) > 1 {
                port, err := strconv.Atoi(os.Args[1])
                if err != nil {
                        fmt.Printf("❌ Parâmetro inválido: %s\n", os.Args[1]) // Corrigido: \n explícito
                        return
                }

                // Carrega certificados TLS se disponíveis (opcional)
                cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
                if err == nil {
                        sslConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
                        logMessage("Certificados TLS carregados com sucesso")
                } else {
                        logMessage("Executando sem certificados TLS")
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
                        fmt.Printf("⚙️  Configurando porta %d...\n", port) // Corrigido: \n explícito

                        if err := createSystemdService(port, execPath); err != nil {
                                fmt.Printf("❌ Erro criando service: %v\n", err) // Corrigido: \n explícito
                                fmt.Print("📌 Pressione Enter para continuar...")
                                waitForEnter()
                                continue
                        }

                        if err := enableAndStartService(port); err != nil {
                                fmt.Printf("❌ Erro iniciando service: %v\n", err) // Corrigido: \n explícito
                                fmt.Print("📌 Pressione Enter para continuar...")
                                waitForEnter()
                                continue
                        }

                        fmt.Printf("✅ Proxy multiprotocolo iniciado na porta %d\n", port) // Corrigido: \n explícito
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
                                if err := stopAndDisableService(port); err != nil {
                                        fmt.Printf("❌ Erro ao parar service: %v\n", err) // Corrigido: \n explícito
                                } else {
                                        fmt.Printf("✅ Porta %d encerrada com sucesso\n", port) // Corrigido: \n explícito
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

func startProxy(port int) {
        addr := fmt.Sprintf(":%d", port)
        listener, err := net.Listen("tcp", addr)
        if err != nil {
                logMessage(fmt.Sprintf("Erro iniciando listener na porta %d: %v", port, err))
                return
        }
        defer listener.Close()

        pidFile := fmt.Sprintf("%s/proxyws_%d.pid", pidFileDir, port)
        if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
                logMessage(fmt.Sprintf("Falha ao gravar PID file: %v", err))
        }

        logMessage(fmt.Sprintf("Proxy multiprotocolo iniciado na porta %d", port))

        // Criar canal para sinais de interrupção
        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

        // Goroutine para captura de sinais
        go func() {
                for {
                        sig := <-sigCh
                        logMessage(fmt.Sprintf("Sinal %v recebido, mantendo proxy ativo", sig))
                }
        }()

        for {
                conn, err := listener.Accept()
                if err != nil {
                        // Se erro temporário, continuar aceitando
                        if ne, ok := err.(net.Error); ok && ne.Temporary() {
                                logMessage(fmt.Sprintf("Erro temporário na porta %d: %v", port, err))
                                time.Sleep(50 * time.Millisecond)
                                continue
                        }
                        logMessage(fmt.Sprintf("Erro fatal na porta %d: %v", port, err))
                        break
                }

                // Usa a função multiprotocolo para lidar com todas as conexões
                go handleConnection(conn)
        }

        logMessage(fmt.Sprintf("Proxy encerrado na porta %d", port))
        os.Remove(pidFile)
}
