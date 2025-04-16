#!/bin/bash

set -e

WHITELIST_URL="https://cloudjf.com.br/whitelistip.txt"
PROXY_CPP_URL="https://raw.githubusercontent.com/jeanfraga95/proxyjf/refs/heads/main/proxy10.cpp"
PROXY_FILENAME="proxy10.cpp"
EXECUTABLE_NAME="proxyjf"

echo "🔍 Verificando IP atual..."
CURRENT_IP=$(curl -s https://api.ipify.org)
AUTHORIZED_IPS=$(curl -s "$WHITELIST_URL")

if echo "$AUTHORIZED_IPS" | grep -q "$CURRENT_IP"; then
    echo "🟢 IP autorizado: $CURRENT_IP"
else
    echo "❌ Este IP ($CURRENT_IP) não está autorizado a instalar o proxy."
    exit 1
fi

echo "📦 Instalando dependências..."
apt update && apt install -y \
    g++ make curl \
    libssl-dev libevent-dev \
    systemd net-tools lsof

echo "⬇️ Baixando código do proxy..."
curl -s -o $PROXY_FILENAME "$PROXY_CPP_URL"

echo "⚙️ Compilando proxy..."
g++ -std=c++17 -o $EXECUTABLE_NAME $PROXY_FILENAME \
    -lssl -lcrypto -levent -pthread

echo "🚀 Instalando o proxy como comando global: proxyjf"
mv $EXECUTABLE_NAME /usr/local/bin/proxyjf
chmod +x /usr/local/bin/proxyjf

echo "🧹 Limpando arquivo fonte..."
rm -f $PROXY_FILENAME

echo "🧼 Limpando cache DNS..."
if command -v systemd-resolve &> /dev/null; then
    systemd-resolve --flush-caches
elif command -v resolvectl &> /dev/null; then
    resolvectl flush-caches
else
    echo "⚠️ Comando de flush DNS não encontrado. Recomendado reiniciar o serviço de rede."
fi

echo "✅ Instalação finalizada com sucesso. Use o comando: proxyjf"
