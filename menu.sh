#!/bin/bash

# ═══════════════════════════════════════════════════════════════
#  Proxy C — Menu de controle (com suporte a Modo Agressivo)
#  Repositório: https://github.com/jeanfraga95/proxyjf
# ═══════════════════════════════════════════════════════════════

PORTS_FILE="/opt/proxyc/ports"
PROXY_BIN="/opt/proxyc/proxy"
MENU_SELF="$0"

REPO_OWNER="jeanfraga95"
REPO_NAME="proxyjf"
GITHUB_API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents"
RAW_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main"
SHA_CACHE="/opt/proxyc/.last_sha_main_c"

# ── Cores ─────────────────────────────────────────────────────
RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[1;33m'
CYAN=$'\e[0;36m'
WHITE=$'\e[1;37m'
BLUE=$'\e[0;34m'
MAGENTA=$'\e[0;35m'
BOLD=$'\e[1m'
DIM=$'\e[2m'
RESET=$'\e[0m'

# ── Trap ──────────────────────────────────────────────────────
trap "printf '%s' '${CURSOR_SHOW}'; tput cnorm 2>/dev/null; exit" INT TERM EXIT

# ═══════════════════════════════════════════════════════════════
#  Utilitários (mantidos)
# ═══════════════════════════════════════════════════════════════

get_cpu_usage() { ... }   # (mesmo código anterior)

# ... (todas as funções get_mem, get_color_bar, etc. permanecem iguais)

# ═══════════════════════════════════════════════════════════════
#  Gerenciamento de portas com Modo Agressivo
# ═══════════════════════════════════════════════════════════════

add_proxy_port() {
    local port=$1 status=${2:-"C"} aggressive=${3:-0}

    if is_port_in_use "$port"; then
        echo "${YELLOW}  ⚠  A porta ${port} já está em uso.${RESET}"
        return 1
    fi

    local cmd="${PROXY_BIN} --port ${port} --status ${status}"
    [ "$aggressive" -eq 1 ] && cmd="${cmd} --aggressive"

    local svc="/etc/systemd/system/proxyc${port}.service"
    cat <<EOF | sudo tee "$svc" > /dev/null
[Unit]
Description=proxyc${port}
After=network.target

[Service]
LimitNOFILE=infinity
LimitNPROC=infinity
LimitMEMLOCK=infinity
LimitSTACK=infinity
LimitCORE=0
LimitAS=infinity
LimitRSS=infinity
LimitCPU=infinity
LimitFSIZE=infinity
Type=simple
ExecStart=${cmd}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "proxyc${port}.service" >/dev/null 2>&1
    sudo systemctl start  "proxyc${port}.service"

    echo "$port" >> "$PORTS_FILE"
    echo "${GREEN}  ✔  Porta ${port} ativada com sucesso!${RESET}"
    [ "$aggressive" -eq 1 ] && echo "     ${YELLOW}→ Modo Agressivo ativado${RESET}"
}

# ═══════════════════════════════════════════════════════════════
#  Alterar status + Modo Agressivo
# ═══════════════════════════════════════════════════════════════

change_port_status() {
    # ... (código anterior mantido)
    # Adicione no final da função a opção de ativar/desativar agressivo
    prompt "  ${CYAN}Ativar Modo Agressivo? (s/N):${RESET} " use_aggressive
    if [[ "$use_aggressive" =~ ^[Ss]$ ]]; then
        aggressive=1
    else
        aggressive=0
    fi

    local cmd="${PROXY_BIN} --port ${port} --status ${new_status}"
    [ "$aggressive" -eq 1 ] && cmd="${cmd} --aggressive"

    sudo sed -i "s|ExecStart=.*|ExecStart=${cmd}|" "$svc_file"
    sudo systemctl daemon-reload
    sudo systemctl restart "proxyc${port}.service"

    echo "${GREEN}  ✔  Porta ${port} atualizada.${RESET}"
    [ "$aggressive" -eq 1 ] && echo "     ${YELLOW}→ Modo Agressivo: ATIVADO${RESET}"
}

# ═══════════════════════════════════════════════════════════════
#  Função principal de adicionar porta (com pergunta agressivo)
# ═══════════════════════════════════════════════════════════════

add_proxy_port_interactive() {
    stop_live_header
    clear

    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s  %s%s  Abrir Nova Porta%s%42s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n\n" "$CYAN" "$RESET"

    prompt "  ${CYAN}Porta (ex: 8080):${RESET} " port
    while ! [[ $port =~ ^[0-9]+$ ]]; do
        echo "${RED}  Porta inválida.${RESET}"
        prompt "  ${CYAN}Porta:${RESET} " port
    done

    prompt "  ${CYAN}Status (ex: SSH, VPN, @rg0n):${RESET} " status
    [ -z "$status" ] && status="C"

    prompt "  ${CYAN}Ativar Modo Agressivo? (s/N):${RESET} " agg
    aggressive=0
    [[ "$agg" =~ ^[Ss]$ ]] && aggressive=1

    add_proxy_port "$port" "$status" "$aggressive"
    pause
}

# ═══════════════════════════════════════════════════════════════
#  Menu Principal Atualizado
# ═══════════════════════════════════════════════════════════════

draw_menu() {
    # ... (cabeçalho mantido igual)
    # Atualize as opções:

    printf "%s║%s   %s1%s  %sAbrir porta (com agressivo)%s     %s2%s  %sFechar porta%s              %s║%s\n" \
        "$CYAN" "$RESET" "$GREEN" "$RESET" "$WHITE" "$RESET" "$GREEN" "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    # ... resto do menu
}

# No loop principal, altere a opção 1:
case $option in
    1)  add_proxy_port_interactive ;;
    # ... resto igual
esac
