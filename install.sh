#!/bin/bash

set -e

INSTALL_DIR="/opt/proxyjf"
REPO_URL="https://github.com/jeanfraga95/proxyjf.git"
PROXY_FILES_PATH="arquivos-proxy"

# Function to check OS compatibility
check_os_compatibility() {
    echo "Verificando compatibilidade do sistema operacional..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            case "$VERSION_ID" in
                "18.04"|"20.04"|"22.04"|"24.04")
                    echo "Ubuntu $VERSION_ID é suportado."
                    ;;
                *)
                    echo "Versão do Ubuntu não suportada: $VERSION_ID. Saindo."
                    exit 1
                    ;;
            esac
        else
            echo "Sistema operacional não suportado: $ID. Este instalador é para Ubuntu 18.04, 20.04, 22.04 ou 24.04. Saindo."
            exit 1
        fi
    else
        echo "Não é possível determinar o sistema operacional. Saindo."
        exit 1
    fi
}

# Function to install dependencies
install_dependencies() {
    echo "Instalando dependências..."
    sudo apt install -y python3 python3-pip openssl git
    pip3 install websockets
    echo "Dependências instaladas."
}

# Function to download proxy files
download_proxy_files() {
    echo "Baixando arquivos do proxy..."
    if [ -d "$INSTALL_DIR" ]; then
        echo "Instalação de proxy existente encontrada. Atualizando..."
        sudo rm -rf "$INSTALL_DIR"
    fi
    sudo git clone "$REPO_URL" "$INSTALL_DIR"
    sudo mv "$INSTALL_DIR/$PROXY_FILES_PATH"/* "$INSTALL_DIR"/
    sudo rm -rf "$INSTALL_DIR/$PROXY_FILES_PATH"
    echo "Proxy files downloaded and moved to $INSTALL_DIR."
}

# Function to set up proxyjf command
setup_proxyjf_command() {
    echo "Configurando o proxyjf..."
    SCRIPT_PATH="$INSTALL_DIR/network_proxy_server/proxy_server.py"
    COMMAND_PATH="/usr/local/bin/proxyjf"

    # Create a wrapper script to run the Python application
    echo "#!/bin/bash" | sudo tee "$COMMAND_PATH"
    echo "python3 $SCRIPT_PATH" | sudo tee -a "$COMMAND_PATH"
    sudo chmod +x "$COMMAND_PATH"
    echo "Comando proxyjf configurado. Agora você pode executar 'sudo proxyjf' para abrir o menu do proxy."
}

# Main installation process
main() {
    check_os_compatibility
    install_dependencies
    download_proxy_files
    setup_proxyjf_command
    echo "Instalação concluída!"
}

main


