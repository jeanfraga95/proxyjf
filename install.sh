#!/bin/bash

set -e

INSTALL_DIR="/opt/proxyjf"
REPO_URL="https://github.com/jeanfraga95/proxyjf.git"

# Verifica compatibilidade do sistema operacional
check_os_compatibility() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            case "$VERSION_ID" in
                "18.04"|"20.04"|"22.04"|"24.04")
                    ;;
                *)
                    echo "Versão do Ubuntu não suportada: $VERSION_ID."
                    exit 1
                    ;;
            esac
        else
            echo "Sistema operacional não suportado."
            exit 1
        fi
    else
        echo "Não foi possível detectar o sistema operacional."
        exit 1
    fi
}

# Instala dependências necessárias
install_dependencies() {
    echo "Instalando dependências, aguarde..."
    sudo apt update -qq > /dev/null
    sudo apt install -y python3 python3-pip openssl git > /dev/null
    python3 -m pip install --upgrade pip > /dev/null 2>&1
    python3 -m pip install websockets > /dev/null 2>&1
}

# Baixa os arquivos do proxy
download_proxy_files() {
    if [ -d "$INSTALL_DIR" ]; then
        sudo rm -rf "$INSTALL_DIR"
    fi
    sudo git clone -q "$REPO_URL" "$INSTALL_DIR"
}

# Configura o comando global proxyjf
setup_proxyjf_command() {
    SCRIPT_PATH="$INSTALL_DIR/network_proxy_server/proxy_server.py"
    COMMAND_PATH="/usr/local/bin/proxyjf"

    sudo bash -c "echo '#!/bin/bash' > $COMMAND_PATH"
    sudo bash -c "echo 'python3 $SCRIPT_PATH' >> $COMMAND_PATH"
    sudo chmod +x "$COMMAND_PATH"
}

# Processo principal de instalação
main() {
    echo "Iniciando instalação do ProxyJF..."
    check_os_compatibility
    install_dependencies
    download_proxy_files
    setup_proxyjf_command
    echo "Instalação concluída!"
    echo "Use o comando: sudo proxyjf"
}

main
