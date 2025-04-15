#!/bin/bash

# === CONFIGURAÇÕES ===
GIST_IPS_URL="https://gist.githubusercontent.com/jeanfraga95/f3b21a20cc0fe583a9ba5edfdf8742ae/raw/ef1cef0e3a972d3102a252c9efa6932c74a76b97/gistfile1.txt"
REPO_URL="https://github.com/jeanfraga95/proxyjf.git"
BIN_NAME="proxyjf"
DESTINO="/usr/local/bin"

# === FUNÇÕES ===
verificar_so() {
    echo "🔍 Verificando sistema operacional..."
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
            echo "⛔ Sistema $ID não suportado. Apenas Ubuntu e Debian são permitidos."
            exit 1
        fi
        VERSAO=$(echo "$VERSION_ID" | cut -d'.' -f1)
        if [[ "$ID" == "ubuntu" && ! "$VERSAO" =~ ^(18|20|22|24)$ ]]; then
            echo "⛔ Versão do Ubuntu ($VERSION_ID) não suportada."
            exit 1
        fi
    else
        echo "⛔ Não foi possível identificar o sistema operacional."
        exit 1
    fi
}

verificar_ip_autorizado() {
    echo "🌐 Verificando IP público..."
    MEU_IP=$(curl -s https://ipinfo.io/ip)
    echo "🔎 IP da máquina: $MEU_IP"

    AUTORIZADO=$(curl -s "$GIST_IPS_URL" | grep -Fx "$MEU_IP")

    if [[ -z "$AUTORIZADO" ]]; then
        echo "⛔ Este IP ($MEU_IP) não está autorizado a instalar o proxy."
        exit 1
    fi

    echo "✅ IP autorizado."
}

instalar_dependencias() {
    echo "📦 Instalando dependências..."
    apt update && apt install -y g++ curl git
}

clonar_compilar_instalar() {
    echo "📥 Clonando repositório..."
    git clone "$REPO_URL"
    cd proxyjf || exit 1

    echo "🛠️ Compilando proxy..."
    g++ -o $BIN_NAME proxy.cpp -pthread

    echo "🚚 Movendo binário para $DESTINO"
    mv $BIN_NAME $DESTINO

    echo "🧹 Limpando arquivos..."
    cd ..
    rm -rf proxyjf

    echo "✅ Instalação concluída. Use o comando: $BIN_NAME"
}

# === EXECUÇÃO ===
verificar_so
verificar_ip_autorizado
instalar_dependencias
clonar_compilar_instalar
