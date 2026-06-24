#!/bin/bash

# ═══════════════════════════════════════════════════════════════
#  Proxy C — Menu de controle
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

CURSOR_HIDE=$'\e[?25l'
CURSOR_SHOW=$'\e[?25h'

trap "printf '%s' '${CURSOR_SHOW}'; tput cnorm 2>/dev/null; exit" INT TERM EXIT

# ═══════════════════════════════════════════════════════════════
#  Utilitários
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

get_mem_pct() { _get_mem_raw | awk '{print $1}'; }
get_mem_info() { _get_mem_raw | awk '{printf "%d%% (%d/%d MB)", $1, $2, $3}'; }

get_color_bar() {
    local pct=$1
    local filled=$(( pct * 20 / 100 ))
    local empty=$(( 20 - filled ))
    local bar="" color

    if [ "$pct" -ge 90 ]; then color=$RED
    elif [ "$pct" -ge 60 ]; then color=$YELLOW
    else color=$GREEN
    fi

    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty;  i++)); do bar+="░"; done
    printf "%s%s%s" "$color" "$bar" "$RESET"
}

get_uptime() {
    uptime -p 2>/dev/null | sed 's/up //' || echo "N/A"
}

get_port_status_symbol() {
    if sudo systemctl is-active --quiet "proxyc${1}.service" 2>/dev/null; then
        printf "%s●%s" "$GREEN" "$RESET"
    else
        printf "%s●%s" "$RED" "$RESET"
    fi
}

# ═══════════════════════════════════════════════════════════════
#  Live Header (CPU + MEM)
# ═══════════════════════════════════════════════════════════════

_live_header_pid=""

start_live_header() {
    stop_live_header
    (
        while true; do
            local cpu_pct mem_pct mem_info cpu_bar mem_bar
            cpu_pct=$(get_cpu_usage)
            mem_pct=$(get_mem_pct)
            mem_info=$(get_mem_info)
            cpu_bar=$(get_color_bar "$cpu_pct")
            mem_bar=$(get_color_bar "$mem_pct")

            printf "\0337"  # save cursor

            tput cup 3 0 2>/dev/null
            printf "%s║%s  %sCPU%s  %s  %3s%%                              %s║%s" \
                "$CYAN" "$RESET" "$DIM" "$RESET" "$cpu_bar" "$cpu_pct" "$CYAN" "$RESET"

            tput cup 4 0 2>/dev/null
            printf "%s║%s  %sMEM%s  %s  %-20s            %s║%s" \
                "$CYAN" "$RESET" "$DIM" "$RESET" "$mem_bar" "$mem_info" "$CYAN" "$RESET"

            printf "\0338"  # restore cursor
            sleep 2
        done
    ) &
    _live_header_pid=$!
}

stop_live_header() {
    if [ -n "$_live_header_pid" ] && kill -0 "$_live_header_pid" 2>/dev/null; then
        kill "$_live_header_pid" 2>/dev/null
        wait "$_live_header_pid" 2>/dev/null 2>&1
    fi
    _live_header_pid=""
}

# ═══════════════════════════════════════════════════════════════
#  Gerenciamento de Portas
# ═══════════════════════════════════════════════════════════════

is_port_in_use() {
    local port=$1
    netstat -tuln 2>/dev/null | grep -q ":${port}\b" && return 0
    ss -tuln 2>/dev/null | grep -q ":${port}\b" && return 0
    return 1
}

add_proxy_port() {
    local port=$1 status=${2:-"C"}
    if is_port_in_use "$port"; then
        echo "${YELLOW}  ⚠  A porta ${port} já está em uso.${RESET}"
        return 1
    fi

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
ExecStart=${PROXY_BIN} --port ${port} --status ${status}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "proxyc${port}.service" >/dev/null
    sudo systemctl start  "proxyc${port}.service" >/dev/null
    echo "$port" >> "$PORTS_FILE"
}

del_proxy_port() {
    local port=$1
    sudo systemctl disable --now "proxyc${port}.service" 2>/dev/null
    sudo rm -f "/etc/systemd/system/proxyc${port}.service"
    sudo systemctl daemon-reload
    sed -i "/^${port}$/d" "$PORTS_FILE"
}

restart_proxy_port() {
    local port=$1
    if ! grep -q "^${port}$" "$PORTS_FILE" 2>/dev/null; then
        echo "${RED}  ✗  Porta ${port} não registrada.${RESET}"
        return 1
    fi
    sudo systemctl restart "proxyc${port}.service"
    echo "${GREEN}  ✔  Porta ${port} reiniciada.${RESET}"
}

# ═══════════════════════════════════════════════════════════════
#  Atualização
# ═══════════════════════════════════════════════════════════════

stop_all_proxies() {
    [ -s "$PORTS_FILE" ] || return
    while read -r port; do
        sudo systemctl stop "proxyc${port}.service" 2>/dev/null
    done < "$PORTS_FILE"
}

start_all_proxies() {
    [ -s "$PORTS_FILE" ] || return
    while read -r port; do
        sudo systemctl start "proxyc${port}.service" 2>/dev/null
    done < "$PORTS_FILE"
}

check_and_update() {
    stop_live_header
    clear

    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s  %s%s  Verificar / Atualizar Proxy%s%32s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n\n" "$CYAN" "$RESET"

    command -v curl >/dev/null || { echo "${RED}✗ curl não encontrado${RESET}"; pause; return; }

    echo "  ${DIM}Consultando repositório...${RESET}"

    local remote_c remote_menu
    remote_c=$(curl -sf "${GITHUB_API}/main.c" -H "Accept: application/vnd.github.v3+json" | grep '"sha"' | head -1 | awk -F'"' '{print $4}')
    remote_menu=$(curl -sf "${GITHUB_API}/menu.sh" -H "Accept: application/vnd.github.v3+json" | grep '"sha"' | head -1 | awk -F'"' '{print $4}')

    local local_menu_sha
    local_menu_sha=$( { printf "blob %s\0" "$(wc -c < "$MENU_SELF")"; cat "$MENU_SELF"; } | sha1sum | awk '{print $1}' )

    local update_proxy=0 update_menu=0
    [ -n "$remote_c" ] && [ "$remote_c" != "$(cat "$SHA_CACHE" 2>/dev/null)" ] && update_proxy=1
    [ -n "$remote_menu" ] && [ "$remote_menu" != "$local_menu_sha" ] && update_menu=1

    if [ $update_proxy -eq 0 ] && [ $update_menu -eq 0 ]; then
        echo "  ${GREEN}✔ Tudo atualizado.${RESET}"
        pause; return
    fi

    if [ $update_proxy -eq 1 ]; then
        echo "  ${CYAN}▶ Atualizando proxy...${RESET}"
        stop_all_proxies

        local tmp_c tmp_bin
        tmp_c=$(mktemp /tmp/proxy_XXXX.c)
        tmp_bin=$(mktemp /tmp/proxy_XXXX)

        if curl -sf "${RAW_URL}/main.c" -o "$tmp_c" && gcc -O2 -pthread "$tmp_c" -o "$tmp_bin"; then
            sudo mkdir -p /opt/proxyc
            sudo cp "$tmp_bin" "$PROXY_BIN"
            sudo chmod +x "$PROXY_BIN"
            echo "$remote_c" | sudo tee "$SHA_CACHE" >/dev/null
            echo "  ${GREEN}✔ Proxy atualizado.${RESET}"
        else
            echo "  ${RED}✗ Falha ao atualizar proxy.${RESET}"
        fi
        rm -f "$tmp_c" "$tmp_bin"
    fi

    if [ $update_menu -eq 1 ]; then
        echo "  ${CYAN}▶ Atualizando menu...${RESET}"
        local tmp_menu=$(mktemp /tmp/menu_XXXX.sh)
        if curl -sf "${RAW_URL}/menu.sh" -o "$tmp_menu" && grep -q "#!/bin/bash" "$tmp_menu"; then
            sudo cp "$tmp_menu" "$MENU_SELF"
            sudo chmod +x "$MENU_SELF"
            rm -f "$tmp_menu"
            echo "  ${GREEN}✔ Menu atualizado. Reiniciando...${RESET}"
            sleep 1
            exec "$MENU_SELF"
        else
            echo "  ${RED}✗ Falha ao atualizar menu.${RESET}"
        fi
    fi

    start_all_proxies
    echo; pause
}

# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

prompt() { printf "%s" "$1"; read -r "$2"; }

pause() {
    printf "\n  Pressione qualquer tecla para voltar... "
    read -r _
}

# ═══════════════════════════════════════════════════════════════
#  Desenho do Menu
# ═══════════════════════════════════════════════════════════════

draw_menu() {
    local up_time=$(get_uptime)
    local cpu_pct=$(get_cpu_usage)
    local mem_pct=$(get_mem_pct)
    local mem_info=$(get_mem_info)
    local cpu_bar=$(get_color_bar "$cpu_pct")
    local mem_bar=$(get_color_bar "$mem_pct")

    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s %s%s Proxy C  %s%sv1.5%s                 %suptime: %-18s%s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "$DIM" "$RESET" \
        "$DIM" "$up_time" "$RESET" "$CYAN" "$RESET"
    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"

    # Linhas do live header
    printf "%s║%s  %sCPU%s  %s  %3s%%                              %s║%s\n" \
        "$CYAN" "$RESET" "$DIM" "$RESET" "$cpu_bar" "$cpu_pct" "$CYAN" "$RESET"
    printf "%s║%s  %sMEM%s  %s  %-20s            %s║%s\n" \
        "$CYAN" "$RESET" "$DIM" "$RESET" "$mem_bar" "$mem_info" "$CYAN" "$RESET"

    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"

    # Portas ativas
    printf "%s║%s  %sPortas ativas:%s" "$CYAN" "$RESET" "$DIM" "$RESET"
    if [ ! -s "$PORTS_FILE" ]; then
        printf "  %snenhuma%s%38s%s║%s\n" "$YELLOW" "$RESET" "" "$CYAN" "$RESET"
    else
        while read -r port; do
            printf "  %s %s%s%s" "$(get_port_status_symbol "$port")" "$WHITE" "$port" "$RESET"
        done < "$PORTS_FILE"
        printf "\n%s║%s%62s%s║%s\n" "$CYAN" "$RESET" "" "$CYAN" "$RESET"
    fi

    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"
    printf "%s║%s                                                              %s║%s\n" "$CYAN" "$RESET" "$CYAN" "$RESET"
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
    printf "%s║%s                                                              %s║%s\n" "$CYAN" "$RESET" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n" "$CYAN" "$RESET"
    echo
}

# ═══════════════════════════════════════════════════════════════
#  Loop Principal
# ═══════════════════════════════════════════════════════════════

show_menu() {
    stop_live_header
    clear
    printf "%s" "$CURSOR_HIDE"
    draw_menu
    start_live_header

    prompt "   ${YELLOW}→ Selecione uma opção: ${RESET}" option
    stop_live_header

    case $option in
        1)
            clear
            prompt "  ${CYAN}Porta:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo "${RED}  Porta inválida.${RESET}"
                prompt "  ${CYAN}Porta:${RESET} " port
            done
            prompt "  ${CYAN}Status (vazio = padrão):${RESET} " status
            add_proxy_port "$port" "$status"
            echo "${GREEN}  ✔  Porta ${port} ativada.${RESET}"
            pause
            ;;
        2)
            clear
            prompt "  ${CYAN}Porta:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo "${RED}  Porta inválida.${RESET}"
                prompt "  ${CYAN}Porta:${RESET} " port
            done
            del_proxy_port "$port"
            echo "${GREEN}  ✔  Porta ${port} fechada.${RESET}"
            pause
            ;;
        3)
            clear
            if [ ! -s "$PORTS_FILE" ]; then
                echo "${YELLOW}  Nenhuma porta ativa.${RESET}"
                pause; return
            fi
            echo "  ${DIM}Portas abertas:${RESET}"
            while read -r p; do
                printf "    %s %s%s%s\n" "$(get_port_status_symbol "$p")" "$WHITE" "$p" "$RESET"
            done < "$PORTS_FILE"
            echo
            prompt "  ${CYAN}Porta para reiniciar:${RESET} " port
            restart_proxy_port "$port"
            pause
            ;;
        4)
            # Alterar status (pode manter sua função original se preferir)
            echo "${YELLOW}Funcionalidade em desenvolvimento...${RESET}"
            pause
            ;;
        5|6|7|8|9|0)
            echo "${YELLOW}Opção ${option} ainda não implementada nesta versão corrigida.${RESET}"
            pause
            ;;
        *)
            echo "${RED}Opção inválida.${RESET}"
            sleep 1
            ;;
    esac
}

# Bootstrap
[ ! -f "$PORTS_FILE" ] && sudo touch "$PORTS_FILE" 2>/dev/null

while true; do
    show_menu
done
