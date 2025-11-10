#!/bin/bash
# rustyproxy Installer (C Version)

TOTAL_STEPS=9
CURRENT_STEP=0

show_progress() {
    PERCENT=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    echo "Progresso: [${PERCENT}%] - $1"
}

error_exit() {
    echo -e "\nErro: $1"
    exit 1
}

increment_step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
}

if [ "$EUID" -ne 0 ]; then
    error_exit "EXECUTE COMO ROOT"
else
    clear
    show_progress "Atualizando repositórios..."
    export DEBIAN_FRONTEND=noninteractive
     > /dev/null 2>&1 || error_exit "Falha ao atualizar repositórios"
    increment_step

    show_progress "Verificando sistema..."
    if ! command -v lsb_release &> /dev/null; then
        apt install lsb-release -y > /dev/null 2>&1
    fi
    increment_step

    OS_NAME=$(lsb_release -is)
    VERSION=$(lsb_release -rs)

    case $OS_NAME in
        Ubuntu)
            case $VERSION in 24.*|22.*|20.*|18.*) ;; *) error_exit "Ubuntu suportado: 18,20,22,24";; esac ;;
        Debian)
            case $VERSION in 12*|11*|10*|9*) ;; *) error_exit "Debian suportado: 9,10,11,12";; esac ;;
        *) error_exit "Use Ubuntu ou Debian." ;;
    esac
    increment_step

    show_progress "Atualizando sistema..."
     > /dev/null 2>&1
    apt install build-essential git -y > /dev/null 2>&1 || error_exit "Falha ao instalar pacotes"
    increment_step

    show_progress "Criando diretório /opt/rustyproxy..."
    mkdir -p /opt/proxyc > /dev/null 2>&1
    increment_step

    show_progress "Clonando e compilando RustyProxy (C)..."
    if [ -d "/root/ProxyC" ]; then rm -rf /root/ProxyC; fi
    git clone https://github.com/jeanfraga95/proxyjf.git /root/ProxyC > /dev/null 2>&1 || error_exit "Falha no git clone"
    cd /root/ProxyC

    make || error_exit "Falha na compilação"
    increment_step

    show_progress "Instalando binários..."
    make install || error_exit "Falha na instalação"
    increment_step

    show_progress "Limpando..."
    cd /root && rm -rf /root/ProxyC
    increment_step

    echo "Instalação concluída! Digite 'proxyc' para abrir o menu."
fi



