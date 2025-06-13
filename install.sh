#!/bin/bash

set -e

INSTALL_DIR="/opt/proxyjf"
REPO_URL="https://github.com/jeanfraga95/proxyjf.git"

# Verifica compatibilidade do sistema operacional
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

# Instala dependências necessárias
install_dependencies() {
    echo "Instalando dependências..."
    sudo apt install -y python3 python3-pip openssl git
    python3 -m pip install --upgrade pip
    python3 -m pip install websockets
    echo "Dependências instaladas."
}

# Baixa os arquivos do proxy
download_proxy_files() {
    echo "Baixando arquivos do proxy..."
    if [ -d "$INSTALL_DIR" ]; then
        echo "Instalação existente encontrada. Atualizando..."
        sudo rm -rf "$INSTALL_DIR"
    fi
    sudo git clone "$REPO_URL" "$INSTALL_DIR"
    echo "Arquivos do proxy baixados para $INSTALL_DIR."
}

# Configura o comando global proxyjf
setup_proxyjf_command() {
    echo "Configurando o proxyjf..."
    SCRIPT_PATH="$INSTALL_DIR/network_proxy_server/proxy_server.py"
    COMMAND_PATH="/usr/local/bin/proxyjf"

    sudo bash -c "echo '#!/bin/bash' > $COMMAND_PATH"
    sudo bash -c "echo 'python3 $SCRIPT_PATH' >> $COMMAND_PATH"
    sudo chmod +x "$COMMAND_PATH"

    echo "Comando proxyjf configurado. Agora você pode executar 'sudo proxyjf' para abrir o menu do proxy."
}

# Processo principal de instalação
main() {
    check_os_compatibility
    install_dependencies
    download_proxy_files
    setup_proxyjf_command
    echo "Instalação concluída com sucesso!"
}

main
