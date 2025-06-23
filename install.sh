#!/bin/bash

# ============================================================================
# INSTALADOR DO PROXY JF - MULTIPROTOCOLO SSH PROXY
# ============================================================================
# Autor: Jean Fraga
# Repositório: https://github.com/jeanfraga95/proxyjf
# Suporte: Ubuntu 18.04, 20.04, 22.04, 24.04
# Versão: 1.0
# Data: $(date '+%Y-%m-%d')
# ============================================================================
# 
# DESCRIÇÃO:
# Instalador automático para o Proxy JF - um proxy multiprotocolo SSH que 
# suporta WebSocket Security, SOCKS4/5, HTTP/HTTPS e TCP genérico, todos 
# redirecionando para autenticação OpenSSH.
#
# FUNCIONALIDADES:
# - Verificação automática de sistema Ubuntu 18/20/22/24
# - Instalação completa de dependências (Git, Go 1.21.5)
# - Download e compilação automática do proxy
# - Configuração completa do sistema com logs e systemd
# - Interface visual moderna com progress tracking
# - Script de desinstalação incluído
#
# USO:
# wget https://raw.githubusercontent.com/SEU_REPO/proxyjf_installer.sh
# chmod +x proxyjf_installer.sh
# sudo ./proxyjf_installer.sh
#
# APÓS INSTALAÇÃO:
# sudo proxyjf  # Para iniciar o menu interativo
#
# ============================================================================

set -e  # Para execução em caso de erro

# ============================================================================
# CONFIGURAÇÕES E VARIÁVEIS GLOBAIS
# ============================================================================

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variáveis de configuração
REPO_URL="https://github.com/jeanfraga95/proxyjf.git"
INSTALL_DIR="/opt/proxyjf"
BIN_DIR="/usr/local/bin"
LOG_FILE="/var/log/proxyjf_install.log"
GO_VERSION="1.21.5"

# Variáveis de sistema
ARCH=""
GO_ARCH=""
UBUNTU_VERSION=""

# ============================================================================
# FUNÇÕES AUXILIARES E INTERFACE
# ============================================================================

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    🚀 PROXY JF INSTALLER 🚀                 ║"
    echo "║                  Multiprotocolo SSH Proxy                    ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Suporta: WebSocket Security, SOCKS4/5, HTTP/HTTPS          ║"
    echo "║  Sistemas: Ubuntu 18.04, 20.04, 22.04, 24.04                ║"
    echo "║  Redirecionamento: OpenSSH (porta 22)                       ║"
    echo "║  Repositório: github.com/jeanfraga95/proxyjf                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
}

log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$LOG_FILE"
    echo -e "$message"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
    log_message "[STEP] $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log_message "[SUCCESS] $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log_message "[ERROR] $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log_message "[WARNING] $1"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
    log_message "[INFO] $1"
}

# ============================================================================
# VERIFICAÇÕES DO SISTEMA
# ============================================================================

check_root() {
    print_step "Verificando permissões de root..."
    if [[ $EUID -ne 0 ]]; then
        print_error "Este script deve ser executado como root!"
        print_info "Execute: sudo $0"
        exit 1
    fi
    print_success "Executando como root ✓"
}

check_ubuntu_version() {
    print_step "Verificando versão do Ubuntu..."
    
    if [[ ! -f /etc/os-release ]]; then
        print_error "Não foi possível detectar o sistema operacional"
        exit 1
    fi
    
    source /etc/os-release
    
    if [[ "$ID" != "ubuntu" ]]; then
        print_error "Este instalador é apenas para Ubuntu!"
        print_info "Sistema detectado: $ID"
        exit 1
    fi
    
    case "$VERSION_ID" in
        "18.04"|"20.04"|"22.04"|"24.04")
            UBUNTU_VERSION="$VERSION_ID"
            print_success "Ubuntu $VERSION_ID detectado ✓"
            ;;
        *)
            print_error "Versão do Ubuntu não suportada: $VERSION_ID"
            print_info "Versões suportadas: 18.04, 20.04, 22.04, 24.04"
            exit 1
            ;;
    esac
}

check_internet() {
    print_step "Verificando conectividade com internet..."
    
    if ! ping -c 1 google.com &> /dev/null; then
        print_error "Sem conexão com internet!"
        print_info "Verifique sua conexão e tente novamente"
        exit 1
    fi
    
    print_success "Conexão com internet ativa ✓"
}

check_architecture() {
    print_step "Verificando arquitetura do sistema..."
    
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            GO_ARCH="amd64"
            ;;
        aarch64|arm64)
            GO_ARCH="arm64"
            ;;
        armv7l)
            GO_ARCH="armv6l"
            ;;
        *)
            print_error "Arquitetura não suportada: $ARCH"
            print_info "Arquiteturas suportadas: x86_64, aarch64, armv7l"
            exit 1
            ;;
    esac
    
    print_success "Arquitetura $ARCH ($GO_ARCH) suportada ✓"
}

# ============================================================================
# INSTALAÇÃO DE DEPENDÊNCIAS
# ============================================================================

update_system() {
    print_step "Atualizando repositórios do sistema..."
    
    if apt-get update -qq > /dev/null 2>&1; then
        print_success "Repositórios atualizados ✓"
    else
        print_error "Falha ao atualizar repositórios"
        exit 1
    fi
}

install_basic_packages() {
    print_step "Instalando pacotes básicos..."
    
    local packages=(
        "curl"
        "wget"
        "git"
        "build-essential"
        "software-properties-common"
        "apt-transport-https"
        "ca-certificates"
        "gnupg"
        "lsb-release"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            print_info "Instalando $package..."
            if apt-get install -y "$package" > /dev/null 2>&1; then
                print_info "$package instalado ✓"
            else
                print_error "Falha ao instalar $package"
                exit 1
            fi
        else
            print_info "$package já está instalado ✓"
        fi
    done
    
    print_success "Pacotes básicos instalados ✓"
}

install_golang() {
    print_step "Instalando Go $GO_VERSION..."
    
    # Remove instalações antigas do Go
    if [[ -d "/usr/local/go" ]]; then
        print_info "Removendo instalação anterior do Go..."
        rm -rf /usr/local/go
    fi
    
    # Download do Go
    local go_file="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    local go_url="https://golang.org/dl/${go_file}"
    
    print_info "Baixando Go $GO_VERSION para $GO_ARCH..."
    if wget -q "$go_url" -O "/tmp/$go_file"; then
        print_info "Download do Go concluído ✓"
    else
        print_error "Falha no download do Go"
        exit 1
    fi
    
    if [[ ! -f "/tmp/$go_file" ]]; then
        print_error "Arquivo do Go não encontrado após download"
        exit 1
    fi
    
    # Extração
    print_info "Extraindo Go..."
    if tar -C /usr/local -xzf "/tmp/$go_file"; then
        print_info "Go extraído com sucesso ✓"
    else
        print_error "Falha na extração do Go"
        exit 1
    fi
    
    # Configuração do PATH
    if ! grep -q "/usr/local/go/bin" /etc/environment; then
        echo 'PATH="/usr/local/go/bin:$PATH"' >> /etc/environment
        print_info "PATH do Go adicionado ao /etc/environment ✓"
    fi
    
    # Configuração para sessão atual
    export PATH="/usr/local/go/bin:$PATH"
    
    # Limpeza
    rm -f "/tmp/$go_file"
    
    # Verificação
    if /usr/local/go/bin/go version > /dev/null 2>&1; then
        local installed_version=$(/usr/local/go/bin/go version | awk '{print $3}')
        print_success "Go instalado: $installed_version ✓"
    else
        print_error "Falha na instalação do Go"
        exit 1
    fi
}

verify_installations() {
    print_step "Verificando instalações..."
    
    # Verificar Git
    if command -v git > /dev/null 2>&1; then
        local git_version=$(git --version | awk '{print $3}')
        print_success "Git $git_version ✓"
    else
        print_error "Git não encontrado"
        exit 1
    fi
    
    # Verificar Go
    if /usr/local/go/bin/go version > /dev/null 2>&1; then
        local go_version=$(/usr/local/go/bin/go version | awk '{print $3}')
        print_success "Go $go_version ✓"
    else
        print_error "Go não encontrado"
        exit 1
    fi
    
    print_success "Todas as dependências verificadas ✓"
}

# ============================================================================
# DOWNLOAD E COMPILAÇÃO
# ============================================================================

download_repository() {
    print_step "Baixando repositório do GitHub..."
    
    # Remove diretório existente se houver
    if [[ -d "$INSTALL_DIR" ]]; then
        print_info "Removendo instalação anterior..."
        rm -rf "$INSTALL_DIR"
    fi
    
    # Criar diretório de instalação
    mkdir -p "$INSTALL_DIR"
    
    # Clonar repositório
    print_info "Clonando $REPO_URL..."
    if git clone "$REPO_URL" "$INSTALL_DIR" > /dev/null 2>&1; then
        print_success "Repositório clonado com sucesso ✓"
    else
        print_error "Falha ao clonar repositório"
        print_info "Verifique se o repositório existe e está acessível"
        exit 1
    fi
    
    # Verificar se o arquivo proxy.go existe
    if [[ ! -f "$INSTALL_DIR/proxy.go" ]]; then
        print_error "Arquivo proxy.go não encontrado no repositório"
        print_info "Estrutura do repositório:"
        ls -la "$INSTALL_DIR"
        exit 1
    fi
    
    print_success "Código fonte baixado ✓"
}

compile_proxy() {
    print_step "Compilando o proxy..."
    
    cd "$INSTALL_DIR"
    
    # Inicializar módulo Go se necessário
    if [[ ! -f "go.mod" ]]; then
        print_info "Inicializando módulo Go..."
        /usr/local/go/bin/go mod init proxyjf > /dev/null 2>&1
    fi
    
    # Compilar o proxy
    print_info "Compilando proxy.go..."
    if /usr/local/go/bin/go build -o proxyjf proxy.go; then
        print_success "Proxy compilado com sucesso ✓"
    else
        print_error "Falha na compilação do proxy"
        print_info "Verifique se o código Go está correto"
        exit 1
    fi
    
    # Verificar se o binário foi criado
    if [[ ! -f "$INSTALL_DIR/proxyjf" ]]; then
        print_error "Binário do proxy não foi criado"
        exit 1
    fi
    
    # Verificar se o binário é executável
    if [[ ! -x "$INSTALL_DIR/proxyjf" ]]; then
        chmod +x "$INSTALL_DIR/proxyjf"
        print_info "Permissões de execução aplicadas ✓"
    fi
    
    print_success "Compilação concluída ✓"
}

configure_permissions() {
    print_step "Configurando permissões e links..."
    
    # Tornar o binário executável
    chmod +x "$INSTALL_DIR/proxyjf"
    
    # Criar link simbólico no PATH
    if [[ -L "$BIN_DIR/proxyjf" ]]; then
        rm -f "$BIN_DIR/proxyjf"
    fi
    
    if ln -s "$INSTALL_DIR/proxyjf" "$BIN_DIR/proxyjf"; then
        print_info "Link simbólico criado ✓"
    else
        print_error "Falha ao criar link simbólico"
        exit 1
    fi
    
    # Verificar se o link foi criado corretamente
    if [[ -L "$BIN_DIR/proxyjf" ]] && [[ -e "$BIN_DIR/proxyjf" ]]; then
        print_success "Link simbólico criado em $BIN_DIR/proxyjf ✓"
    else
        print_error "Link simbólico não funciona corretamente"
        exit 1
    fi
    
    print_success "Permissões configuradas ✓"
}

# ============================================================================
# CONFIGURAÇÃO DO SISTEMA
# ============================================================================

create_directories() {
    print_step "Criando diretórios necessários..."
    
    local directories=(
        "/var/log"
        "/var/run"
        "/etc/systemd/system"
    )
    
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            if mkdir -p "$dir"; then
                print_info "Diretório criado: $dir ✓"
            else
                print_error "Falha ao criar diretório: $dir"
                exit 1
            fi
        fi
    done
    
    print_success "Diretórios criados ✓"
}

configure_logging() {
    print_step "Configurando sistema de logs..."
    
    # Criar arquivo de log do proxy
    local proxy_log="/var/log/proxyws.log"
    touch "$proxy_log"
    chmod 644 "$proxy_log"
    
    # Configurar logrotate para o proxy
    cat > /etc/logrotate.d/proxyjf << 'EOF'
/var/log/proxyws.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF
    
    if [[ -f "/etc/logrotate.d/proxyjf" ]]; then
        print_info "Configuração do logrotate criada ✓"
    else
        print_warning "Falha ao criar configuração do logrotate"
    fi
    
    print_success "Sistema de logs configurado ✓"
}

configure_systemd() {
    print_step "Configurando integração com systemd..."
    
    # Verificar se systemd está funcionando
    if systemctl --version > /dev/null 2>&1; then
        print_success "Systemd detectado e funcionando ✓"
    else
        print_warning "Systemd não detectado - algumas funcionalidades podem não funcionar"
        return 0
    fi
    
    # Recarregar daemon do systemd
    if systemctl daemon-reload; then
        print_info "Daemon do systemd recarregado ✓"
    else
        print_warning "Falha ao recarregar daemon do systemd"
    fi
    
    print_success "Integração com systemd configurada ✓"
}

test_installation() {
    print_step "Testando instalação..."
    
    # Testar se o comando proxyjf está disponível
    if command -v proxyjf > /dev/null 2>&1; then
        print_success "Comando 'proxyjf' disponível no PATH ✓"
    else
        print_error "Comando 'proxyjf' não encontrado no PATH"
        exit 1
    fi
    
    # Testar se o binário executa (sem argumentos para não travar)
    if timeout 2s "$INSTALL_DIR/proxyjf" 2>/dev/null || [[ $? -eq 124 ]]; then
        print_success "Binário executa corretamente ✓"
    else
        print_info "Binário pode não ter opção --help (normal para este proxy)"
    fi
    
    # Verificar permissões
    if [[ -x "$INSTALL_DIR/proxyjf" ]]; then
        print_success "Permissões de execução corretas ✓"
    else
        print_error "Permissões de execução incorretas"
        exit 1
    fi
    
    print_success "Instalação testada ✓"
}

# ============================================================================
# FINALIZAÇÃO
# ============================================================================

create_uninstaller() {
    print_step "Criando script de desinstalação..."
    
    cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash

echo "🗑️  Desinstalando Proxy JF..."
echo "================================"

# Parar todos os serviços do proxy
echo "Parando serviços do proxy..."
systemctl stop 'proxyws@*' 2>/dev/null || true
systemctl disable 'proxyws@*' 2>/dev/null || true

# Remover arquivos de serviço
echo "Removendo arquivos de serviço..."
rm -f /etc/systemd/system/proxyws@*.service

# Recarregar systemd
systemctl daemon-reload 2>/dev/null || true

# Remover link simbólico
echo "Removendo link simbólico..."
rm -f /usr/local/bin/proxyjf

# Remover diretório de instalação
echo "Removendo diretório de instalação..."
rm -rf /opt/proxyjf

# Remover logs
echo "Removendo logs..."
rm -f /var/log/proxyws.log
rm -f /var/log/proxyjf_install.log

# Remover configuração do logrotate
echo "Removendo configuração do logrotate..."
rm -f /etc/logrotate.d/proxyjf

echo ""
echo "✅ Proxy JF desinstalado com sucesso!"
echo "ℹ️  O Go permanece instalado no sistema"
echo "ℹ️  Para remover o Go também, execute:"
echo "   sudo rm -rf /usr/local/go"
echo "   sudo sed -i '/\/usr\/local\/go\/bin/d' /etc/environment"
EOF
    
    chmod +x "$INSTALL_DIR/uninstall.sh"
    
    if [[ -x "$INSTALL_DIR/uninstall.sh" ]]; then
        print_success "Script de desinstalação criado ✓"
    else
        print_warning "Falha ao criar script de desinstalação"
    fi
}

show_usage_instructions() {
    print_step "Mostrando instruções de uso..."
    
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    🎉 INSTALAÇÃO CONCLUÍDA! 🎉              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}📋 COMO USAR O PROXY JF:${NC}"
    echo
    echo -e "${YELLOW}1. Iniciar o proxy:${NC}"
    echo -e "   ${BLUE}sudo proxyjf${NC}"
    echo
    echo -e "${YELLOW}2. Menu interativo disponível com opções:${NC}"
    echo -e "   • 1️⃣  Abrir nova porta (multiprotocolo)"
    echo -e "   • 2️⃣  Fechar porta"
    echo -e "   • 3️⃣  Listar portas ativas"
    echo -e "   • 4️⃣  Status do sistema"
    echo -e "   • 5️⃣  Ver logs em tempo real"
    echo -e "   • 0️⃣  Sair (mantém proxies ativos)"
    echo
    echo -e "${YELLOW}3. Gerenciar via systemctl:${NC}"
    echo -e "   ${BLUE}systemctl status proxyws@PORTA${NC}    # Ver status"
    echo -e "   ${BLUE}systemctl stop proxyws@PORTA${NC}      # Parar porta"
    echo -e "   ${BLUE}systemctl start proxyws@PORTA${NC}     # Iniciar porta"
    echo
    echo -e "${YELLOW}4. Monitorar logs:${NC}"
    echo -e "   ${BLUE}tail -f /var/log/proxyws.log${NC}      # Logs do proxy"
    echo -e "   ${BLUE}tail -f /var/log/proxyjf_install.log${NC} # Logs da instalação"
    echo
    echo -e "${YELLOW}5. Desinstalar completamente:${NC}"
    echo -e "   ${BLUE}sudo $INSTALL_DIR/uninstall.sh${NC}"
    echo
    echo -e "${CYAN}🔧 PROTOCOLOS SUPORTADOS (AUTOMÁTICO):${NC}"
    echo -e "   • ${GREEN}WebSocket Security${NC} → HTTP/1.1 101 ProxyEuro + Headers WS"
    echo -e "   • ${GREEN}SOCKS4/SOCKS5${NC}      → HTTP/1.1 200 OK"
    echo -e "   • ${GREEN}HTTP/HTTPS${NC}         → HTTP/1.1 101 ProxyEuro"
    echo -e "   • ${GREEN}TCP Genérico${NC}       → HTTP/1.1 101 ProxyEuro"
    echo
    echo -e "${CYAN}📍 ARQUIVOS IMPORTANTES:${NC}"
    echo -e "   • Binário: ${BLUE}$INSTALL_DIR/proxyjf${NC}"
    echo -e "   • Comando: ${BLUE}proxyjf${NC} (disponível globalmente)"
    echo -e "   • Logs: ${BLUE}/var/log/proxyws.log${NC}"
    echo -e "   • Desinstalador: ${BLUE}$INSTALL_DIR/uninstall.sh${NC}"
    echo
    echo -e "${CYAN}🎯 EXEMPLO DE USO RÁPIDO:${NC}"
    echo -e "   ${BLUE}sudo proxyjf${NC}                    # Iniciar menu"
    echo -e "   ${BLUE}# Escolher opção 1 e digitar 8080${NC}  # Abrir porta"
    echo -e "   ${BLUE}# Testar: curl --socks5 IP:8080 httpbin.org/ip${NC}"
    echo
    echo -e "${GREEN}✅ Proxy JF instalado e pronto para uso!${NC}"
    echo -e "${GREEN}🚀 Todos os protocolos redirecionam para SSH (porta 22)${NC}"
    echo
}

# ============================================================================
# FUNÇÕES PRINCIPAIS DE EXECUÇÃO
# ============================================================================

run_system_checks() {
    print_step "Iniciando verificações do sistema..."
    
    check_root
    check_ubuntu_version
    check_internet
    check_architecture
    
    print_success "Todas as verificações do sistema passaram ✓"
    echo
}

run_dependency_installation() {
    print_step "Iniciando instalação de dependências..."
    
    update_system
    install_basic_packages
    install_golang
    verify_installations
    
    print_success "Todas as dependências instaladas ✓"
    echo
}

run_download_and_compilation() {
    print_step "Iniciando download e compilação..."
    
    download_repository
    compile_proxy
    configure_permissions
    
    print_success "Download e compilação concluídos ✓"
    echo
}

run_system_configuration() {
    print_step "Iniciando configuração do sistema..."
    
    create_directories
    configure_logging
    configure_systemd
    test_installation
    
    print_success "Configuração do sistema concluída ✓"
    echo
}

run_finalization() {
    print_step "Finalizando instalação..."
    
    create_uninstaller
    show_usage_instructions
    
    log_message "=== INSTALAÇÃO DO PROXY JF CONCLUÍDA COM SUCESSO ==="
    print_success "Instalação finalizada com sucesso! ✓"
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    # Mostrar banner
    print_banner
    
    # Criar arquivo de log
    touch "$LOG_FILE" 2>/dev/null || {
        echo "Erro: Não foi possível criar arquivo de log. Execute como root."
        exit 1
    }
    
    log_message "=== INÍCIO DA INSTALAÇÃO DO PROXY JF ==="
    log_message "Sistema: $(uname -a)"
    log_message "Usuário: $(whoami)"
    log_message "Data: $(date)"
    
    print_info "🚀 Iniciando instalação do Proxy JF..."
    print_info "📝 Log da instalação: $LOG_FILE"
    print_info "🔗 Repositório: $REPO_URL"
    echo
    
    # Executar todas as etapas
    run_system_checks
    run_dependency_installation
    run_download_and_compilation
    run_system_configuration
    run_finalization
    
    # Log final
    log_message "Instalação concluída com sucesso em $(date)"
    log_message "Sistema: Ubuntu $UBUNTU_VERSION ($ARCH)"
    log_message "Go: $GO_VERSION"
    log_message "Proxy instalado em: $INSTALL_DIR"
}

# ============================================================================
# TRATAMENTO DE ERROS E SINAIS
# ============================================================================

# Função para limpeza em caso de erro
cleanup_on_error() {
    print_error "Instalação interrompida!"
    print_info "Limpando arquivos temporários..."
    
    # Remover arquivos temporários
    rm -f /tmp/go*.tar.gz 2>/dev/null || true
    
    # Log do erro
    log_message "=== INSTALAÇÃO INTERROMPIDA COM ERRO ==="
    
    print_info "Logs disponíveis em: $LOG_FILE"
    exit 1
}

# Capturar sinais de interrupção
trap cleanup_on_error INT TERM

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

# Verificar se está sendo executado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

# ============================================================================
# FIM DO INSTALADOR
# ==========================================================================
