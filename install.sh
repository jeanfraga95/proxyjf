#!/bin/bash
set -e

clear
echo "🔧 Iniciando instalação do Proxy JF..."

# Obtém o IP atual da máquina
echo "🔍 Verificando IP atual..."
IP_ATUAL=$(curl -s https://ipinfo.io/ip || curl -s https://ifconfig.me)
echo "🌐 IP detectado: $IP_ATUAL"

# Baixa a lista de IPs permitidos do link
echo "📥 Baixando lista de IPs permitidos..."
IP_LISTA=$(curl -s http://cloudjf.com.br/whitelistip.txt)

# Verifica se o IP atual está na lista
if echo "$IP_LISTA" | grep -q "$IP_ATUAL"; then
    echo "✅ IP autorizado!"
else
    echo "❌ Este IP ($IP_ATUAL) não está autorizado a instalar o proxy."
    exit 1
fi

sleep 1

echo "📦 Instalando dependências..."
apt update -y && apt install -y curl g++ make libssl-dev libboost-all-dev dos2unix

# Remove código anterior se existir
rm -f proxy.cpp proxyjf

echo "📥 Baixando código-fonte do proxy..."
curl -sSL https://raw.githubusercontent.com/jeanfraga95/proxyjf/refs/heads/main/proxy10.cpp -o proxy.cpp

# Corrige quebras de linha CRLF, se houver
dos2unix proxy.cpp >/dev/null 2>&1 || true

if [ ! -f "proxy.cpp" ]; then
    echo "❌ Erro: proxy.cpp não foi baixado corretamente."
    exit 1
fi

echo "🔨 Compilando o proxy com suporte a SSL e Threads..."
g++ proxy.cpp -o proxyjf -lpthread -lssl -lcrypto

echo "📂 Instalando o binário em /usr/local/bin..."
mv -f proxyjf /usr/local/bin/proxyjf
chmod +x /usr/local/bin/proxyjf

echo "🧹 Limpando arquivos temporários..."
rm -f proxy.cpp

echo ""
echo "✅ Instalação concluída com sucesso!"
echo "🚀 Execute com: proxyjf"
