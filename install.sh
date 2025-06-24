#!/bin/bash

# === CORES ===
GREEN="\033[1;32m"
RED="\033[1;31m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
NC="\033[0m"

# === VARIÁVEIS ===
INSTALL_DIR="/opt/proxyapp"
BIN_NAME="proxy"
GO_FILE="proxy.go"
GO_REQUIRED_VERSION="1.16"
GO_INSTALL_PATH="/usr/local/go"
GO_BINARY="$GO_INSTALL_PATH/bin/go"
DEPS=(curl wget unzip git g++ make libevent-dev)

# === BARRA DE PROGRESSO ===
progress_bar() {
  echo -ne "${BLUE}"
  for i in {1..20}; do
    echo -n "#"
    sleep 0.1
  done
  echo -e "${NC}"
}

# === VERIFICA SISTEMA ===
check_system() {
  if ! grep -qi "ubuntu" /etc/os-release; then
    echo -e "${RED}❌ Este script só funciona em sistemas Ubuntu.${NC}"
    exit 1
  fi
}

# === MENU ===
user_choice() {
  echo -e "${YELLOW}O que deseja fazer?${NC}"
  select opt in "Instalar/Atualizar Proxy" "Remover Proxy" "Sair"; do
    case $opt in
      "Instalar/Atualizar Proxy") ACTION="install"; break ;;
      "Remover Proxy") ACTION="remove"; break ;;
      "Sair") exit 0 ;;
      *) echo -e "${RED}Opção inválida.${NC}" ;;
    esac
  done
}

# === REMOVE PROXY ===
remove_proxy() {
  echo -e "${YELLOW}Removendo proxy...${NC}"
  progress_bar

  if [ -d "$INSTALL_DIR" ]; then
    systemctl stop proxy.service 2>/dev/null
    systemctl disable proxy.service 2>/dev/null
    rm -rf "$INSTALL_DIR"
    rm -f /etc/systemd/system/proxy.service
    systemctl daemon-reexec
    echo -e "${GREEN}✔ Proxy removido com sucesso.${NC}"
  else
    echo -e "${RED}⚠ Nenhum proxy instalado encontrado.${NC}"
  fi
}

# === INSTALA DEPENDÊNCIAS PADRÃO ===
install_dependencies() {
  MISSING=()
  for pkg in "${DEPS[@]}"; do
    dpkg -s "$pkg" &> /dev/null || MISSING+=("$pkg")
  done

  if [ "${#MISSING[@]}" -gt 0 ]; then
    echo -e "${YELLOW}Instalando dependências...${NC}"
    progress_bar
    apt-get update -qq
    apt-get install -y "${MISSING[@]}" > /dev/null
  else
    echo -e "${GREEN}✔ Todas as dependências já estão instaladas.${NC}"
  fi
}

# === VERIFICA E INSTALA GO CORRETO ===
ensure_go() {
  echo -e "${YELLOW}Verificando Go...${NC}"

  CURRENT_VERSION=$($GO_BINARY version 2>/dev/null | awk '{print $3}' | sed 's/go//')

  if [ -z "$CURRENT_VERSION" ] || dpkg --compare-versions "$CURRENT_VERSION" "lt" "$GO_REQUIRED_VERSION"; then
    echo -e "${YELLOW}⚠ Instalando Go 1.22.3...${NC}"
    cd /tmp
    wget -q https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
    rm -rf "$GO_INSTALL_PATH"
    tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz

    # Adiciona ao PATH permanentemente se ainda não existir
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
      echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi
    export PATH=$PATH:/usr/local/go/bin

    echo -e "${GREEN}✔ Go 1.22.3 instalado com sucesso.${NC}"
  else
    echo -e "${GREEN}✔ Go $CURRENT_VERSION já está instalado.${NC}"
  fi
}

# === COMPILA O PROXY COM O GO CORRETO ===
build_proxy() {
  echo -e "${YELLOW}Compilando proxy...${NC}"
  progress_bar

  if [ ! -f "$GO_FILE" ]; then
    echo -e "${RED}❌ Arquivo $GO_FILE não encontrado no diretório atual.${NC}"
    exit 1
  fi

  $GO_BINARY build -o "$BIN_NAME" "$GO_FILE"

  if [ ! -f "$BIN_NAME" ]; then
    echo -e "${RED}❌ Erro ao compilar $GO_FILE.${NC}"
    exit 1
  fi
}

# === INSTALA O PROXY ===
install_proxy() {
  build_proxy

  echo -e "${YELLOW}Instalando proxy...${NC}"
  progress_bar

  remove_proxy

  mkdir -p "$INSTALL_DIR"
  cp "$BIN_NAME" "$INSTALL_DIR"

  cat <<EOF > /etc/systemd/system/proxy.service
[Unit]
Description=Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$BIN_NAME
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable proxy.service
  systemctl start proxy.service

  echo -e "${GREEN}✅ Instalação concluída com sucesso!${NC}"
  echo -e "${BLUE}▶ Para iniciar manualmente: ${INSTALL_DIR}/${BIN_NAME}${NC}"
}

# === EXECUÇÃO PRINCIPAL ===
check_system
user_choice

if [ "$ACTION" = "remove" ]; then
  remove_proxy
else
  install_dependencies
  ensure_go
  install_proxy
fi
