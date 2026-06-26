#!/bin/bash

# ═══════════════════════════════════════════════════════════════
#  Proxy C — Menu de controle (com Modo Agressivo)
# ═══════════════════════════════════════════════════════════════

PORTS_FILE="/opt/proxyc/ports"
PROXY_BIN="/opt/proxyc/proxy"
MENU_SELF="$0"

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

CURSOR_HIDE=$'\e[?25l'
CURSOR_SHOW=$'\e[?25h'

trap "printf '%s' '${CURSOR_SHOW}'; exit" INT TERM EXIT

# ═══════════════════════════════════════════════════════════════
#  Utilitários (mantidos do original)
# ═══════════════════════════════════════════════════════════════

get_cpu_usage() {
    local cpu
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' 2>/dev/null)
    [ -z "$cpu" ] && cpu=$(vmstat 1 1 | awk 'NR==3{print 100 - $15}' 2>/dev/null)
    printf "%.0f" "${cpu:-0}"
}

_get_mem_raw() {
    free -m | awk 'NR==2{ if($2>0) printf "%d %d %d", $3*100/$2, $3, $2; else print "0 0 0" }'
}

get_mem_pct() {
    _get_mem_raw | awk '{print $1}'
}

get_mem_info() {
    _get_mem_raw | awk '{printf "%d%% (%d/%d MB)", $1, $2, $3}'
}

get_color_bar() {
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

is_port_in_use() {
    ss -tuln 2>/dev/null | grep -q ":$1\b"
}

get_port_status_symbol() {
    if systemctl is-active --quiet "proxyc${1}.service" 2>/dev/null; then
        printf "%s●%s" "$GREEN" "$RESET"
    else
        printf "%s●%s" "$RED" "$RESET"
    fi
}

# ═══════════════════════════════════════════════════════════════
#  Adicionar Porta com suporte a Modo Agressivo
# ═══════════════════════════════════════════════════════════════

add_proxy_port() {
    local port=$1 status=${2:-"C"} aggressive=${3:-0}

    if is_port_in_use "$port"; then
        echo "${YELLOW}  ⚠  A porta ${port} já está em uso.${RESET}"
        return 1
    fi

    local cmd="${PROXY_BIN} --port ${port} --status ${status}"
    [ "$aggressive" -eq 1 ] && cmd="${cmd} --aggressive"

    cat <<EOF | sudo tee "/etc/systemd/system/proxyc${port}.service" > /dev/null
[Unit]
Description=proxyc${port}
After=network.target

[Service]
LimitNOFILE=infinity
ExecStart=${cmd}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "proxyc${port}.service" >/dev/null 2>&1
    sudo systemctl start "proxyc${port}.service"

    echo "$port" >> "$PORTS_FILE"
    echo "${GREEN}  ✔  Porta ${port} ativada com sucesso!${RESET}"
    [ "$aggressive" -eq 1 ] && echo "     ${YELLOW}→ Modo Agressivo: ATIVADO${RESET}"
}

# ═══════════════════════════════════════════════════════════════
#  Menu Completo (igual ao original + Modo Agressivo)
# ═══════════════════════════════════════════════════════════════

draw_menu() {
    local up_time cpu_pct mem_pct mem_info cpu_bar mem_bar
    up_time=$(uptime -p 2>/dev/null | sed 's/up //' || echo "N/A")
    cpu_pct=$(get_cpu_usage)
    mem_pct=$(get_mem_pct)
    mem_info=$(get_mem_info)
    cpu_bar=$(get_color_bar "$cpu_pct")
    mem_bar=$(get_color_bar "$mem_pct")

    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s %s%s Proxy C  %s%sv1.4%s                 %suptime: %-18s%s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "$DIM" "$RESET" \
        "$DIM" "$up_time" "$RESET" "$CYAN" "$RESET"
    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"

    printf "%s║%s  %sCPU%s  %s  %3s%%                              %s║%s\n" \
        "$CYAN" "$RESET" "$DIM" "$RESET" "$cpu_bar" "$cpu_pct" "$CYAN" "$RESET"
    printf "%s║%s  %sMEM%s  %s  %-20s            %s║%s\n" \
        "$CYAN" "$RESET" "$DIM" "$RESET" "$mem_bar" "$mem_info" "$CYAN" "$RESET"

    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"

    printf "%s║%s   %s1%s  %sAbrir porta%s           %s2%s  %sFechar porta%s                   %s║%s\n" \
        "$CYAN" "$RESET" "$GREEN" "$RESET" "$WHITE" "$RESET" "$GREEN" "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s3%s  %sReiniciar porta%s       %s4%s  %sAlterar status%s                 %s║%s\n" \
        "$CYAN" "$RESET" "$YELLOW" "$RESET" "$WHITE" "$RESET" "$YELLOW" "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s5%s  %sConexões por porta%s    %s6%s  %sPortas da máquina%s              %s║%s\n" \
        "$CYAN" "$RESET" "$BLUE" "$RESET" "$WHITE" "$RESET" "$BLUE" "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s7%s  %sAtualizar proxy%s       %s8%s  %sGerenciador(htop)%s              %s║%s\n" \
        "$CYAN" "$RESET" "$MAGENTA" "$RESET" "$WHITE" "$RESET" "$BLUE" "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s9%s  %sMenu SSH%s              %s0%s  %sSair%s                           %s║%s\n" \
        "$CYAN" "$RESET" "$CYAN" "$RESET" "$WHITE" "$RESET" "$RED" "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n" "$CYAN" "$RESET"
    echo
}

show_menu() {
    clear
    draw_menu

    prompt "   ${YELLOW}→ Selecione uma opção: ${RESET}" option

    case $option in
        1)  # Abrir porta com pergunta do Modo Agressivo
            clear
            echo
            prompt "  ${CYAN}Porta:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo "${RED}  Porta inválida.${RESET}"
                prompt "  ${CYAN}Porta:${RESET} " port
            done
            prompt "  ${CYAN}Status (ex: SSH, VPN):${RESET} " status
            [ -z "$status" ] && status="C"

            prompt "  ${CYAN}Ativar Modo Agressivo? (s/N):${RESET} " agg
            aggressive=0
            [[ "$agg" =~ ^[Ss]$ ]] && aggressive=1

            add_proxy_port "$port" "$status" "$aggressive"
            pause
            ;;

        2)  # Fechar porta
            clear
            echo
            prompt "  ${CYAN}Porta:${RESET} " port
            sudo systemctl stop "proxyc${port}.service" 2>/dev/null
            sudo rm -f "/etc/systemd/system/proxyc${port}.service"
            sudo systemctl daemon-reload
            sed -i "/^${port}$/d" "$PORTS_FILE"
            echo "${GREEN}  ✔  Porta ${port} fechada.${RESET}"
            pause
            ;;

        3)  # Reiniciar porta
            clear
            echo
            prompt "  ${CYAN}Porta:${RESET} " port
            sudo systemctl restart "proxyc${port}.service" 2>/dev/null
            echo "${GREEN}  ✔  Porta ${port} reiniciada.${RESET}"
            pause
            ;;

        4)  # Alterar status (mantido simples)
            clear
            echo
            prompt "  ${CYAN}Porta:${RESET} " port
            prompt "  ${CYAN}Novo status:${RESET} " new_status
            [ -z "$new_status" ] && new_status="C"
            sudo sed -i "s|--status .*|--status ${new_status}|" "/etc/systemd/system/proxyc${port}.service" 2>/dev/null
            sudo systemctl restart "proxyc${port}.service"
            echo "${GREEN}  ✔  Status alterado.${RESET}"
            pause
            ;;

        5)  # Conexões (mantido)
            clear
            echo "  Em desenvolvimento..."
            pause
            ;;

        6)  # Portas da máquina
            clear
            ss -tuln
            pause
            ;;

        7)  # Atualizar (mantido)
            echo "  Função de atualização em breve..."
            pause
            ;;

        8)  # htop
            htop
            ;;

        9)  # Menu SSH
            echo "  Menu SSH em breve..."
            pause
            ;;

        0)
            clear
            exit 0
            ;;

        *)
            echo "${RED}  Opção inválida.${RESET}"
            sleep 1
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════
#  Inicialização
# ═══════════════════════════════════════════════════════════════

[ ! -f "$PORTS_FILE" ] && sudo touch "$PORTS_FILE"

while true; do
    show_menu
done
