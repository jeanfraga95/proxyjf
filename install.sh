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

# === VERIFICA SE É UBUNTU ===
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

# === VERIFICA E INSTALA O GO SE NECESSÁRIO ===
ensure_go() {
  REQUIRED_VERSION="1.16"

  CURRENT_GO=$(go version 2>/dev/null)
  if [[ $? -eq 0 ]]; then
    CURRENT_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if dpkg --compare-versions "$CURRENT_VERSION" "ge" "$REQUIRED_VERSION"; then
      echo -e "${GREEN}✔ Go $CURRENT_VERSION detectado.${NC}"
      return
    else
      echo -e "${YELLOW}⚠ Versão do Go ($CURRENT_VERSION) é antiga. Atualizando...${NC}"
    fi
  else
    echo -e "${YELLOW}⚠ Go não está instalado. Instalando...${NC}"
  fi

  # Instalar Go manualmente
  cd /tmp
  wget -q https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

  echo -e "${GREEN}✔ Go 1.22.3 instalado com sucesso.${NC}"
}

# === COMPILA O PROXY ===
build_proxy() {
  echo -e "${YELLOW}Compilando proxy...${NC}"
  progress_bar
  go build -o "$BIN_NAME" "$GO_FILE"
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
