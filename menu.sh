#!/bin/bash

PORTS_FILE="/opt/proxyc/ports"

# ── Cores (sintaxe $'\e[' — funciona em read -p e printf sem -e) ──────────
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

# ─────────────────────────────────────────────
# Utilitários de sistema
# ─────────────────────────────────────────────

get_cpu_usage() {
    local cpu
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' 2>/dev/null)
    [ -z "$cpu" ] && cpu=$(vmstat 1 1 | awk 'NR==3{print 100 - $15}' 2>/dev/null)
    printf "%.0f" "${cpu:-0}"
}

get_mem_usage() {
    local total used pct
    read -r total used <<< "$(free -m | awk 'NR==2{print $2, $3}')"
    [ -z "$total" ] || [ "$total" -eq 0 ] && { echo "0% (0/0 MB)"; return; }
    pct=$(( used * 100 / total ))
    echo "${pct}% (${used}/${total} MB)"
}

get_cpu_bar() {
    local pct=$1
    local filled=$(( pct * 20 / 100 ))
    local empty=$(( 20 - filled ))
    local bar="" color

    if   [ "$pct" -ge 90 ]; then color=$RED
    elif [ "$pct" -ge 60 ]; then color=$YELLOW
    else                          color=$GREEN
    fi

    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty;  i++)); do bar+="░"; done
    printf "%s%s%s" "$color" "$bar" "$RESET"
}

get_mem_bar() {
    local pct
    pct=$(free -m | awk 'NR==2{printf "%.0f", $3*100/$2}')
    get_cpu_bar "$pct"
}

get_uptime() {
    uptime -p 2>/dev/null | sed 's/up //' || uptime | awk -F',' '{print $1}' | awk '{print $3,$4}'
}

# ─────────────────────────────────────────────
# Verificação de porta em uso
# ─────────────────────────────────────────────

is_port_in_use() {
    local port=$1
    netstat -tuln 2>/dev/null | grep -q ":${port}\b" && return 0
    ss -tuln 2>/dev/null     | grep -q ":${port}\b" && return 0
    return 1
}

# ─────────────────────────────────────────────
# Gerenciamento de portas
# ─────────────────────────────────────────────

add_proxy_port() {
    local port=$1
    local status=${2:-"C"}

    if is_port_in_use "$port"; then
        echo "${YELLOW}  ⚠  A porta ${port} já está em uso.${RESET}"
        return
    fi

    local svc_path="/etc/systemd/system/proxyc${port}.service"
    cat <<EOF | sudo tee "$svc_path" > /dev/null
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
ExecStart=/opt/proxyc/proxy --port ${port} --status ${status}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "proxyc${port}.service"
    sudo systemctl start  "proxyc${port}.service"
    echo "$port" >> "$PORTS_FILE"
}

del_proxy_port() {
    local port=$1
    sudo systemctl disable "proxyc${port}.service"
    sudo systemctl stop    "proxyc${port}.service"
    sudo rm -f "/etc/systemd/system/proxyc${port}.service"
    sudo systemctl daemon-reload
    sed -i "/^${port}$/d" "$PORTS_FILE"
}

restart_proxy_port() {
    local port=$1
    if ! grep -q "^${port}$" "$PORTS_FILE" 2>/dev/null; then
        echo "${RED}  ✗  A porta ${port} não está registrada.${RESET}"
        return 1
    fi
    sudo systemctl restart "proxyc${port}.service"
}

get_port_status() {
    local port=$1
    if sudo systemctl is-active --quiet "proxyc${port}.service" 2>/dev/null; then
        printf "%s●%s" "$GREEN" "$RESET"
    else
        printf "%s●%s" "$RED" "$RESET"
    fi
}

# ─────────────────────────────────────────────
# Helpers de I/O
# ─────────────────────────────────────────────

# Exibe prompt colorido e lê entrada — evita read -p com \033
prompt() {
    printf "%s" "$1"
    read -r "$2"
}

pause() {
    printf "  Pressione qualquer tecla para voltar... "
    read -r _
}

# ─────────────────────────────────────────────
# Menu principal
# ─────────────────────────────────────────────

show_menu() {
    clear

    local cpu_pct mem_info up_time cpu_bar mem_bar
    cpu_pct=$(get_cpu_usage)
    mem_info=$(get_mem_usage)
    up_time=$(get_uptime)
    cpu_bar=$(get_cpu_bar "$cpu_pct")
    mem_bar=$(get_mem_bar)

    # ── Cabeçalho ─────────────────────────────────────────────────────────
    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s  %s%s  Proxy C  %s%sv1.3%s                 %suptime: %-18s%s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "$DIM" "$RESET" "$DIM" "$up_time" "$RESET" "$CYAN" "$RESET"
    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"

    # CPU
    printf "%s║%s  %sCPU%s  %s  %3s%%   %s║%s\n" \
        "$CYAN" "$RESET" "$DIM" "$RESET" "$cpu_bar" "$cpu_pct" "$CYAN" "$RESET"

    # Memória
    printf "%s║%s  %sMEM%s  %s  %-20s%s║%s\n" \
        "$CYAN" "$RESET" "$DIM" "$RESET" "$mem_bar" "$mem_info" "$CYAN" "$RESET"

    # ── Portas ativas ─────────────────────────────────────────────────────
    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"

    if [ ! -s "$PORTS_FILE" ]; then
        printf "%s║%s  %sPortas ativas:%s  %snenhuma%s%38s%s║%s\n" \
            "$CYAN" "$RESET" "$DIM" "$RESET" "$YELLOW" "$RESET" "" "$CYAN" "$RESET"
    else
        printf "%s║%s  %sPortas ativas:%s" "$CYAN" "$RESET" "$DIM" "$RESET"
        while read -r port; do
            printf "  %s %s%s%s" "$(get_port_status "$port")" "$WHITE" "$port" "$RESET"
        done < "$PORTS_FILE"
        printf "\n"
        printf "%s║%s%62s%s║%s\n" "$CYAN" "$RESET" "" "$CYAN" "$RESET"
    fi

    # ── Opções ────────────────────────────────────────────────────────────
    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"
    printf "%s║%s                                                              %s║%s\n" "$CYAN" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s1%s  %sAbrir porta%s           %s2%s  %sFechar porta%s                   %s║%s\n" \
        "$CYAN" "$RESET" "$GREEN" "$RESET" "$WHITE" "$RESET" "$GREEN" "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s3%s  %sReiniciar porta%s       %s4%s  %sGerenciador (htop)%s              %s║%s\n" \
        "$CYAN" "$RESET" "$YELLOW" "$RESET" "$WHITE" "$RESET" "$BLUE" "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s5%s  %sMenu SSH%s              %s0%s  %sSair%s                           %s║%s\n" \
        "$CYAN" "$RESET" "$MAGENTA" "$RESET" "$WHITE" "$RESET" "$RED" "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s                                                              %s║%s\n" "$CYAN" "$RESET" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n" "$CYAN" "$RESET"
    echo

    prompt "   ${YELLOW}→ Selecione uma opção: ${RESET}" option

    case $option in

        # ── Abrir porta ───────────────────────────────────────────────────
        1)
            echo
            prompt "  ${CYAN}Porta:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo "${RED}  Porta inválida.${RESET}"
                prompt "  ${CYAN}Porta:${RESET} " port
            done
            prompt "  ${CYAN}Status de conexão (vazio = padrão):${RESET} " status
            add_proxy_port "$port" "$status"
            [ "$port" == "8080" ] && echo "${YELLOW}  ⚠  A porta 80 requer que a 8080 esteja desativada.${RESET}"
            echo "${GREEN}  ✔  Porta ${port} ativada com sucesso.${RESET}"
            pause
            ;;

        # ── Fechar porta ──────────────────────────────────────────────────
        2)
            echo
            prompt "  ${CYAN}Porta:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo "${RED}  Porta inválida.${RESET}"
                prompt "  ${CYAN}Porta:${RESET} " port
            done
            del_proxy_port "$port"
            echo "${GREEN}  ✔  Porta ${port} fechada com sucesso.${RESET}"
            pause
            ;;

        # ── Reiniciar porta ───────────────────────────────────────────────
        3)
            echo
            if [ ! -s "$PORTS_FILE" ]; then
                echo "${YELLOW}  ⚠  Nenhuma porta ativa para reiniciar.${RESET}"
                pause
                return
            fi
            echo "  ${DIM}Portas abertas:${RESET}"
            while read -r p; do
                printf "    %s  %s%s%s\n" "$(get_port_status "$p")" "$WHITE" "$p" "$RESET"
            done < "$PORTS_FILE"
            echo
            prompt "  ${CYAN}Porta para reiniciar:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo "${RED}  Porta inválida.${RESET}"
                prompt "  ${CYAN}Porta:${RESET} " port
            done
            if restart_proxy_port "$port"; then
                echo "${GREEN}  ✔  Porta ${port} reiniciada com sucesso.${RESET}"
            fi
            pause
            ;;

        # ── Gerenciador ───────────────────────────────────────────────────
        4)
            htop
            ;;

        # ── Menu SSH ──────────────────────────────────────────────────────
        5)
            menu
            ;;

        # ── Sair ──────────────────────────────────────────────────────────
        0)
            echo "${DIM}  Saindo...${RESET}"
            exit 0
            ;;

        *)
            echo "${RED}  Opção inválida.${RESET}"
            sleep 1
            ;;
    esac
}

# ─────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────

[ ! -f "$PORTS_FILE" ] && sudo touch "$PORTS_FILE"

while true; do
    show_menu
done
