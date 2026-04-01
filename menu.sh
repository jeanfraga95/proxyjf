#!/bin/bash

PORTS_FILE="/opt/proxyc/ports"

# Cores e estilos
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─────────────────────────────────────────────
# Utilitários de sistema
# ─────────────────────────────────────────────

get_cpu_usage() {
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' 2>/dev/null)
    if [ -z "$cpu" ]; then
        cpu=$(vmstat 1 1 | awk 'NR==3{print 100 - $15}' 2>/dev/null)
    fi
    printf "%.0f" "${cpu:-0}"
}

get_mem_usage() {
    read total used <<< $(free -m | awk 'NR==2{print $2, $3}')
    if [ -z "$total" ] || [ "$total" -eq 0 ]; then
        echo "0% (0/0 MB)"
        return
    fi
    pct=$(( used * 100 / total ))
    echo "${pct}% (${used}/${total} MB)"
}

get_cpu_bar() {
    local pct=$1
    local filled=$(( pct * 20 / 100 ))
    local empty=$(( 20 - filled ))
    local bar=""

    if   [ "$pct" -ge 90 ]; then color=$RED
    elif [ "$pct" -ge 60 ]; then color=$YELLOW
    else                          color=$GREEN
    fi

    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty;  i++)); do bar+="░"; done
    echo -e "${color}${bar}${RESET}"
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
    if netstat -tuln 2>/dev/null | grep -q ":${port}\b"; then
        return 0
    elif ss -tuln 2>/dev/null | grep -q ":${port}\b"; then
        return 0
    fi
    return 1
}

# ─────────────────────────────────────────────
# Gerenciamento de portas
# ─────────────────────────────────────────────

add_proxy_port() {
    local port=$1
    local status=${2:-"C"}

    if is_port_in_use "$port"; then
        echo -e "${YELLOW}  ⚠  A porta ${port} já está em uso.${RESET}"
        return
    fi

    local command="/opt/proxyc/proxy --port $port --status $status"
    local service_file_path="/etc/systemd/system/proxyc${port}.service"
    local service_file_content="[Unit]
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
ExecStart=${command}
Restart=always

[Install]
WantedBy=multi-user.target"

    echo "$service_file_content" | sudo tee "$service_file_path" > /dev/null
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
        echo -e "${RED}  ✗  A porta ${port} não está registrada.${RESET}"
        return
    fi
    sudo systemctl restart "proxyc${port}.service"
}

get_port_status() {
    local port=$1
    if sudo systemctl is-active --quiet "proxyc${port}.service" 2>/dev/null; then
        echo -e "${GREEN}●${RESET}"
    else
        echo -e "${RED}●${RESET}"
    fi
}

# ─────────────────────────────────────────────
# Menu principal
# ─────────────────────────────────────────────

show_menu() {
    clear

    local cpu_pct mem_info up_time
    cpu_pct=$(get_cpu_usage)
    mem_info=$(get_mem_usage)
    up_time=$(get_uptime)
    local cpu_bar mem_bar
    cpu_bar=$(get_cpu_bar "$cpu_pct")
    mem_bar=$(get_mem_bar)

    # ── Cabeçalho ──────────────────────────────────────────────────────────
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${RESET}  ${BOLD}${WHITE}  Proxy C  ${RESET}${DIM}v1.3${RESET}                 ${DIM}uptime: ${up_time}${RESET}   ${CYAN}║${RESET}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"

    # CPU
    printf "${CYAN}║${RESET}  ${DIM}CPU${RESET}  ${cpu_bar}  %3s%%   " "$cpu_pct"
    echo -e "${CYAN}║${RESET}"

    # Memória
    printf "${CYAN}║${RESET}  ${DIM}MEM${RESET}  ${mem_bar}  %-14s" "$mem_info"
    echo -e " ${CYAN}║${RESET}"

    # ── Portas ativas ──────────────────────────────────────────────────────
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"

    if [ ! -s "$PORTS_FILE" ]; then
        echo -e "${CYAN}║${RESET}  ${DIM}Portas ativas:${RESET}  ${YELLOW}nenhuma${RESET}$(printf '%*s' 38 '')${CYAN}║${RESET}"
    else
        local port_line=""
        while read -r port; do
            local st
            st=$(get_port_status "$port")
            port_line+=" ${st} ${WHITE}${port}${RESET}"
        done < "$PORTS_FILE"
        printf "${CYAN}║${RESET}  ${DIM}Portas ativas:${RESET}  %-45b ${CYAN}║${RESET}\n" "$port_line"
    fi

    # ── Menu de opções ─────────────────────────────────────────────────────
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${CYAN}║${RESET}                                                              ${CYAN}║${RESET}"
    printf "${CYAN}║${RESET}   ${GREEN}1${RESET}  ${WHITE}Abrir porta${RESET}           ${GREEN}2${RESET}  ${WHITE}Fechar porta${RESET}                   ${CYAN}║${RESET}\n"
    printf "${CYAN}║${RESET}   ${YELLOW}3${RESET}  ${WHITE}Reiniciar porta${RESET}       ${BLUE}4${RESET}  ${WHITE}Gerenciador (htop)${RESET}              ${CYAN}║${RESET}\n"
    printf "${CYAN}║${RESET}   ${MAGENTA}5${RESET}  ${WHITE}Menu SSH${RESET}              ${RED}0${RESET}  ${WHITE}Sair${RESET}                           ${CYAN}║${RESET}\n"
    echo -e "${CYAN}║${RESET}                                                              ${CYAN}║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo

    read -rp "   ${YELLOW}→ Selecione uma opção: ${RESET}" option

    case $option in

        # ── Abrir porta ───────────────────────────────────────────────────
        1)
            echo
            read -rp "  ${CYAN}Porta:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo -e "${RED}  Porta inválida.${RESET}"
                read -rp "  ${CYAN}Porta:${RESET} " port
            done
            read -rp "  ${CYAN}Status de conexão (deixe vazio para padrão):${RESET} " status
            add_proxy_port "$port" "$status"
            if [ "$port" == "8080" ]; then
                echo -e "${YELLOW}  ⚠  A porta 80 requer que a 8080 esteja desativada.${RESET}"
            fi
            echo -e "${GREEN}  ✔  Porta ${port} ativada com sucesso.${RESET}"
            read -rp "  Pressione qualquer tecla para voltar... " _
            ;;

        # ── Fechar porta ──────────────────────────────────────────────────
        2)
            echo
            read -rp "  ${CYAN}Porta:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo -e "${RED}  Porta inválida.${RESET}"
                read -rp "  ${CYAN}Porta:${RESET} " port
            done
            del_proxy_port "$port"
            echo -e "${GREEN}  ✔  Porta ${port} fechada com sucesso.${RESET}"
            read -rp "  Pressione qualquer tecla para voltar... " _
            ;;

        # ── Reiniciar porta ───────────────────────────────────────────────
        3)
            echo
            if [ ! -s "$PORTS_FILE" ]; then
                echo -e "${YELLOW}  ⚠  Nenhuma porta ativa para reiniciar.${RESET}"
                read -rp "  Pressione qualquer tecla para voltar... " _
                return
            fi
            echo -e "  ${DIM}Portas abertas:${RESET}"
            while read -r p; do
                st=$(get_port_status "$p")
                echo -e "    ${st}  ${WHITE}${p}${RESET}"
            done < "$PORTS_FILE"
            echo
            read -rp "  ${CYAN}Porta para reiniciar:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo -e "${RED}  Porta inválida.${RESET}"
                read -rp "  ${CYAN}Porta:${RESET} " port
            done
            restart_proxy_port "$port"
            echo -e "${GREEN}  ✔  Porta ${port} reiniciada com sucesso.${RESET}"
            read -rp "  Pressione qualquer tecla para voltar... " _
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
            echo -e "${DIM}  Saindo...${RESET}"
            exit 0
            ;;

        *)
            echo -e "${RED}  Opção inválida.${RESET}"
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
