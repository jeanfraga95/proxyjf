#!/bin/bash
set -e

# Limpa a tela
clear

echo "🔧 Iniciando instalação do Proxy JF..."

# Verificando IP da máquina
echo "🔍 Verificando IP atual..."
ip_publico=$(curl -s https://ipinfo.io/ip || curl -s https://ifconfig.me)
echo "🌐 IP detectado: $ip_publico"
sleep 1

# Atualizando pacotes e instalando dependências
echo "📦 Instalando dependências..."
apt update -y && apt install -y git g++ curl make libssl-dev libboost-all-dev dos2unix

# Apagando diretório antigo, se existir
if [ -d "proxyjf" ]; then
    echo "⚠️ Diretório 'proxyjf' já existe. Removendo para prosseguir..."
    rm -rf proxyjf
fi

# Clonando o repositório
echo "📥 Baixando o projeto do GitHub..."
git clone https://github.com/jeanfraga95/proxyjf.git
cd proxyjf

# Corrigindo possíveis quebras de linha do Windows
dos2unix proxy.cpp >/dev/null 2>&1 || true

# Compilando o código-fonte
echo "🔨 Compilando o proxy com suporte a SSL e Threads..."
g++ proxy.cpp -o proxyjf -lpthread -lssl -lcrypto

# Instalando (ou substituindo) o binário
destino="/usr/local/bin/proxyjf"
if [ -f "$destino" ]; then
    echo "♻️ Versão anterior detectada. Atualizando binário existente..."
else
    echo "🆕 Instalando novo binário no sistema..."
fi
mv -f proxyjf "$destino"
chmod +x "$destino"

# Limpando arquivos temporários
echo "🧹 Limpando arquivos temporários..."
cd ..
rm -rf proxyjf

# Finalização
echo ""
echo "✅ Instalação concluída com sucesso!"
echo "📦 O proxy pode ser executado com o comando: proxyjf"
