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

# Sequências de cursor
CURSOR_HIDE=$'\e[?25l'
CURSOR_SHOW=$'\e[?25h'
CURSOR_HOME=$'\e[H'
CLEAR_SCREEN=$'\e[2J'

# ── Trap: garantir que o cursor volte ao sair ─────────────────
trap "printf '%s' '${CURSOR_SHOW}'; tput cnorm 2>/dev/null; exit" INT TERM EXIT

# ═══════════════════════════════════════════════════════════════
#  Utilitários de sistema
# ═══════════════════════════════════════════════════════════════

get_cpu_usage() {
    local cpu
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' 2>/dev/null)
    [ -z "$cpu" ] && cpu=$(vmstat 1 1 | awk 'NR==3{print 100 - $15}' 2>/dev/null)
    printf "%.0f" "${cpu:-0}"
}

# Retorna "pct used total" em uma linha só (evita chamar free 2x)
_get_mem_raw() {
    free -m | awk 'NR==2{ if($2>0) printf "%d %d %d", $3*100/$2, $3, $2; else print "0 0 0" }'
}

get_mem_pct() {
    _get_mem_raw | awk '{print $1}'
}

get_mem_info() {
    _get_mem_raw | awk '{printf "%d%% (%d/%d MB)", $1, $2, $3}' | tr -d '\n'
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

get_uptime() {
    uptime -p 2>/dev/null | sed 's/up //' \
        || uptime | awk -F',' '{print $1}' | awk '{print $3,$4}'
}

# ═══════════════════════════════════════════════════════════════
#  Cabeçalho com CPU/MEM ao vivo (atualiza sem redesenhar o menu)
#  Usa tput cup para mover o cursor para as linhas corretas.
# ═══════════════════════════════════════════════════════════════

# Linha (0-based) onde começa o bloco CPU/MEM no menu
CPU_LINE=3   # linha da barra de CPU
MEM_LINE=4   # linha da barra de MEM

_live_header_pid=""

start_live_header() {
    stop_live_header   # garante que não há loop anterior

    (
        while true; do
            local cpu_pct mem_pct mem_info cpu_bar mem_bar
            cpu_pct=$(get_cpu_usage)
            mem_pct=$(get_mem_pct)
            mem_info=$(get_mem_info)
            cpu_bar=$(get_color_bar "$cpu_pct")
            mem_bar=$(get_color_bar "$mem_pct")

            # Salva posição, move para linha CPU, escreve, restaura
            printf "\0337"   # salva cursor (ESC 7)

            # Linha CPU
            tput cup $CPU_LINE 0 2>/dev/null
            printf "%s║%s  %sCPU%s  %s  %3s%%                              %s║%s" \
                "$CYAN" "$RESET" "$DIM" "$RESET" "$cpu_bar" "$cpu_pct" "$CYAN" "$RESET"

            # Linha MEM
            tput cup $MEM_LINE 0 2>/dev/null
            printf "%s║%s  %sMEM%s  %s  %-20s            %s║%s" \
                "$CYAN" "$RESET" "$DIM" "$RESET" "$mem_bar" "$mem_info" "$CYAN" "$RESET"

            printf "\0338"   # restaura cursor (ESC 8)

            sleep 2
        done
    ) &
    _live_header_pid=$!
}

stop_live_header() {
    if [ -n "$_live_header_pid" ] && kill -0 "$_live_header_pid" 2>/dev/null; then
        kill "$_live_header_pid" 2>/dev/null
        wait "$_live_header_pid" 2>/dev/null
    fi
    _live_header_pid=""
}

# ═══════════════════════════════════════════════════════════════
#  Gerenciamento de portas
# ═══════════════════════════════════════════════════════════════

is_port_in_use() {
    local port=$1
    netstat -tuln 2>/dev/null | grep -q ":${port}\b" && return 0
    ss -tuln 2>/dev/null     | grep -q ":${port}\b" && return 0
    return 1
}

get_port_status_symbol() {
    if sudo systemctl is-active --quiet "proxyc${1}.service" 2>/dev/null; then
        printf "%s●%s" "$GREEN" "$RESET"
    else
        printf "%s●%s" "$RED" "$RESET"
    fi
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

# ═══════════════════════════════════════════════════════════════
#  Todas as portas abertas na máquina + serviço
# ═══════════════════════════════════════════════════════════════

show_open_ports() {
    stop_live_header
    clear

    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s  %s%s  Portas Abertas na Máquina%s%34s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n\n" "$CYAN" "$RESET"

    printf "  %s%-8s %-12s %-20s %s%s\n" "$DIM" "PORTA" "PROTO" "ENDEREÇO" "SERVIÇO/PROCESSO" "$RESET"
    printf "  %s%s%s\n\n" "$DIM" "──────────────────────────────────────────────────────────" "$RESET"

    # ss lista todas as portas em LISTEN — TCP e UDP
    while IFS= read -r line; do
        local proto laddr pid_info port svc addr

        proto=$(awk '{print $1}' <<< "$line")
        laddr=$(awk '{print $5}' <<< "$line")
        pid_info=$(grep -oP 'pid=\K[0-9]+' <<< "$line" | head -1)

        port=$(rev <<< "$laddr" | cut -d: -f1 | rev)
        addr=$(rev <<< "$laddr" | cut -d: -f2- | rev)
        [ "$addr" = "*" ] || [ -z "$addr" ] && addr="0.0.0.0"

        if [ -n "$pid_info" ]; then
            svc=$(ps -p "$pid_info" -o comm= 2>/dev/null | head -1)
        else
            svc=$(awk -v p="$port" '$2 ~ "^"p"/" {print $1; exit}' /etc/services 2>/dev/null)
            [ -z "$svc" ] && svc="-"
        fi

        local color="$RESET"
        grep -q "^${port}$" "$PORTS_FILE" 2>/dev/null && color="$GREEN"

        printf "  %s%-8s %-12s %-20s %s%s\n" \
            "$color" "$port" "$proto" "$addr" "$svc" "$RESET"

    done < <(ss -tlnup 2>/dev/null | awk 'NR>1' | sort -t: -k2 -n)

    echo
    pause
}

# ═══════════════════════════════════════════════════════════════
#  Alterar status de uma porta sem fechar/reabrir
# ═══════════════════════════════════════════════════════════════

change_port_status() {
    stop_live_header
    clear

    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s  %s%s  Alterar Status da Porta%s%36s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n\n" "$CYAN" "$RESET"

    if [ ! -s "$PORTS_FILE" ]; then
        echo "  ${YELLOW}Nenhuma porta aberta.${RESET}"
        echo; pause; return
    fi

    echo "  ${DIM}Portas abertas:${RESET}"
    while read -r p; do
        local svc_file="/etc/systemd/system/proxyc${p}.service"
        local cur_status=""
        if [ -f "$svc_file" ]; then
            cur_status=$(grep 'ExecStart=' "$svc_file" | grep -oP '--status \K\S+')
        fi
        [ -z "$cur_status" ] && cur_status="(padrão)"
        printf "    %s  %s%-6s%s  status: %s%s%s\n" \
            "$(get_port_status_symbol "$p")" \
            "$WHITE" "$p" "$RESET" \
            "$YELLOW" "$cur_status" "$RESET"
    done < "$PORTS_FILE"
    echo

    prompt "  ${CYAN}Porta para alterar:${RESET} " port
    while ! [[ $port =~ ^[0-9]+$ ]]; do
        echo "${RED}  Porta inválida.${RESET}"
        prompt "  ${CYAN}Porta:${RESET} " port
    done

    if ! grep -q "^${port}$" "$PORTS_FILE" 2>/dev/null; then
        echo "${RED}  ✗  Porta ${port} não está registrada no proxy.${RESET}"
        echo; pause; return
    fi

    prompt "  ${CYAN}Novo status (ex: SSH, VPN, @rg0n):${RESET} " new_status
    if [ -z "$new_status" ]; then
        echo "${YELLOW}  Status não pode ser vazio.${RESET}"
        echo; pause; return
    fi

    local svc_file="/etc/systemd/system/proxyc${port}.service"
    if [ ! -f "$svc_file" ]; then
        echo "${RED}  ✗  Arquivo de serviço não encontrado.${RESET}"
        echo; pause; return
    fi

    sudo sed -i "s|ExecStart=.*|ExecStart=${PROXY_BIN} --port ${port} --status ${new_status}|" "$svc_file"
    sudo systemctl daemon-reload
    sudo systemctl restart "proxyc${port}.service"

    echo
    echo "${GREEN}  ✔  Status da porta ${port} alterado para '${new_status}' e serviço reiniciado.${RESET}"
    echo; pause
}

# ═══════════════════════════════════════════════════════════════
#  Conexões ativas por porta  (bug count corrigido)
# ═══════════════════════════════════════════════════════════════

show_connections() {
    stop_live_header
    clear

    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s %s%s Conexões Ativas%s%45s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n\n" "$CYAN" "$RESET"

    if [ ! -s "$PORTS_FILE" ]; then
        echo "  ${YELLOW}Nenhuma porta aberta.${RESET}"
        echo
        pause
        return
    fi

    local total_conn=0

    while read -r port; do
        local sym
        sym=$(get_port_status_symbol "$port")

        # O proxy aceita na porta $port e faz fork() — após o fork o filho
        # faz a ponte cliente<->SSH. As conexões aparecem no ss de duas formas:
        #   1) ESTAB  local=*:$port          peer=IP_CLIENTE:porta_efemera
        #   2) ESTAB  local=IP_LOCAL:$port   peer=IP_CLIENTE:porta_efemera
        # Usamos ss -tnp sem filtro de state para pegar todas as ESTAB na porta.

        local conns_raw
        conns_raw=$(ss -tn 2>/dev/null             | awk -v p=":${port}" '
                /ESTAB/ {
                    # coluna 4 = local addr:port, coluna 5 = peer addr:port
                    if ($4 ~ p) { print $5 }
                }
            '             | sed 's/:[0-9]*$//'             | grep -vE '^(\*|)$'             | sort -u)

        local count=0
        [ -n "$conns_raw" ] && count=$(printf '%s\n' "$conns_raw" | grep -c '^.')

        total_conn=$(( total_conn + count ))

        printf "  %s  %s[%-6s]%s  %s%d usuário(s) conectado(s)%s\n" \
            "$sym" "$WHITE" "$port" "$RESET" "$CYAN" "$count" "$RESET"

        if [ "$count" -gt 0 ]; then
            while IFS= read -r ip; do
                [ -z "$ip" ] && continue
                # Tenta resolver hostname sem travar (timeout 1s)
                local resolved
                resolved=$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')
                [ -z "$resolved" ] && resolved="$ip"
                printf "       %s→  %-20s%s  %s%s%s\n" \
                    "$DIM" "$ip" "$RESET" "$DIM" "$resolved" "$RESET"
            done <<< "$conns_raw"
        fi
        echo
    done < "$PORTS_FILE"

    printf "  %sTotal de IPs conectados: %s%d%s\n\n" "$DIM" "$WHITE" "$total_conn" "$RESET"
    pause
}

# ═══════════════════════════════════════════════════════════════
#  Verificação e atualização silenciosa via GitHub API
# ═══════════════════════════════════════════════════════════════

github_sha() {
    curl -sf "${GITHUB_API}/${1}" \
         -H "Accept: application/vnd.github.v3+json" \
    | grep '"sha"' | head -1 | awk -F'"' '{print $4}'
}

local_git_sha() {
    local file=$1
    [ ! -f "$file" ] && { echo ""; return; }
    local size
    size=$(wc -c < "$file")
    { printf "blob %s\0" "$size"; cat "$file"; } | sha1sum | awk '{print $1}'
}

check_and_update() {
    stop_live_header
    clear

    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s  %s%s  Verificar / Atualizar Proxy%s%32s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n\n" "$CYAN" "$RESET"

    if ! command -v curl &>/dev/null; then
        echo "${RED}  ✗  curl não encontrado. Instale com: apt install curl${RESET}"
        echo; pause; return
    fi

    echo "  ${DIM}Consultando repositório...${RESET}"

    # ── SHAs remotos ──────────────────────────────────────────────────────
    local remote_c remote_menu
    remote_c=$(github_sha "main.c")
    remote_menu=$(github_sha "menu.sh")

    # ── SHAs locais ───────────────────────────────────────────────────────
    local cached_c=""
    [ -f "$SHA_CACHE" ] && cached_c=$(cat "$SHA_CACHE")
    local local_menu
    local_menu=$(local_git_sha "$MENU_SELF")

    # ── Decidir o que atualizar ───────────────────────────────────────────
    local update_proxy=0 update_menu=0

    [ -n "$remote_c" ]    && [ "$remote_c"    != "$cached_c"    ] && update_proxy=1
    [ -n "$remote_menu" ] && [ "$remote_menu" != "$local_menu"  ] && update_menu=1

    if [ "$update_proxy" -eq 0 ] && [ "$update_menu" -eq 0 ]; then
        printf "\r  %s✔  Tudo atualizado.%s\n\n" "$GREEN" "$RESET"
        pause
        return
    fi

    # ── Atualizar proxy (compilar main.c) ─────────────────────────────────
    if [ "$update_proxy" -eq 1 ]; then
        printf "\r  ${CYAN}▶ Atualizando proxy...${RESET}  "

        local tmp_c tmp_bin
        tmp_c=$(mktemp /tmp/proxyjf_main_XXXX.c)
        tmp_bin=$(mktemp /tmp/proxyjf_bin_XXXX)

        if curl -sf "${RAW_URL}/main.c" -o "$tmp_c" \
           && gcc -O2 -pthread "$tmp_c" -o "$tmp_bin" 2>/dev/null; then

            sudo cp "$tmp_bin" "$PROXY_BIN"
            sudo chmod +x "$PROXY_BIN"
            sudo mkdir -p /opt/proxyc
            echo "$remote_c" | sudo tee "$SHA_CACHE" > /dev/null

            # Reinicia todos os serviços silenciosamente
            if [ -s "$PORTS_FILE" ]; then
                while read -r port; do
                    sudo systemctl restart "proxyc${port}.service" 2>/dev/null
                done < "$PORTS_FILE"
            fi

            printf "%s✔%s\n" "$GREEN" "$RESET"
        else
            printf "%s✗%s\n" "$RED" "$RESET"
        fi

        rm -f "$tmp_c" "$tmp_bin"
    fi

    # ── Atualizar menu.sh ─────────────────────────────────────────────────
    if [ "$update_menu" -eq 1 ]; then
        printf "  ${CYAN}▶ Atualizando menu...${RESET}    "

        local tmp_menu
        tmp_menu=$(mktemp /tmp/proxyjf_menu_XXXX.sh)

        if curl -sf "${RAW_URL}/menu.sh" -o "$tmp_menu" \
           && grep -q "#!/bin/bash" "$tmp_menu"; then

            sudo cp "$tmp_menu" "$MENU_SELF"
            sudo chmod +x "$MENU_SELF"
            rm -f "$tmp_menu"

            printf "%s✔%s\n\n" "$GREEN" "$RESET"
            sleep 1
            exec "$MENU_SELF"   # relança com a nova versão
        else
            printf "%s✗%s\n" "$RED" "$RESET"
            rm -f "$tmp_menu"
        fi
    fi

    echo
    pause
}

# ═══════════════════════════════════════════════════════════════
#  Helpers de I/O
# ═══════════════════════════════════════════════════════════════

prompt() {
    printf "%s" "$1"
    read -r "$2"
}

pause() {
    printf "  Pressione qualquer tecla para voltar... "
    read -r _
}

# ═══════════════════════════════════════════════════════════════
#  Desenha o menu (uma vez) e inicia o loop de CPU/MEM ao vivo
# ═══════════════════════════════════════════════════════════════

draw_menu() {
    local up_time cpu_pct mem_pct mem_info cpu_bar mem_bar
    up_time=$(get_uptime)
    cpu_pct=$(get_cpu_usage)
    mem_pct=$(get_mem_pct)
    mem_info=$(get_mem_info)
    cpu_bar=$(get_color_bar "$cpu_pct")
    mem_bar=$(get_color_bar "$mem_pct")

    # ── Cabeçalho ─────────────────────────────────────────────────────────
    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"   # 0
    printf "%s║%s %s%s Proxy C  %s%sv1.4%s                 %suptime: %-18s%s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "$DIM" "$RESET" \
        "$DIM" "$up_time" "$RESET" "$CYAN" "$RESET"                                                   # 1
    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"   # 2

    # linha 3 — CPU (atualizada pelo loop ao vivo)
    printf "%s║%s  %sCPU%s  %s  %3s%%                              %s║%s\n" \
        "$CYAN" "$RESET" "$DIM" "$RESET" "$cpu_bar" "$cpu_pct" "$CYAN" "$RESET"

    # linha 4 — MEM (atualizada pelo loop ao vivo)
    printf "%s║%s  %sMEM%s  %s  %-20s            %s║%s\n" \
        "$CYAN" "$RESET" "$DIM" "$RESET" "$mem_bar" "$mem_info" "$CYAN" "$RESET"

    # ── Portas ativas ─────────────────────────────────────────────────────
    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"

    if [ ! -s "$PORTS_FILE" ]; then
        printf "%s║%s  %sPortas ativas:%s  %snenhuma%s%38s%s║%s\n" \
            "$CYAN" "$RESET" "$DIM" "$RESET" "$YELLOW" "$RESET" "" "$CYAN" "$RESET"
    else
        printf "%s║%s  %sPortas ativas:%s" "$CYAN" "$RESET" "$DIM" "$RESET"
        while read -r port; do
            printf "  %s %s%s%s" "$(get_port_status_symbol "$port")" "$WHITE" "$port" "$RESET"
        done < "$PORTS_FILE"
        printf "\n"
        printf "%s║%s%62s%s║%s\n" "$CYAN" "$RESET" "" "$CYAN" "$RESET"
    fi

    # ── Opções ────────────────────────────────────────────────────────────
    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"
    printf "%s║%s                                                              %s║%s\n" "$CYAN" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s1%s  %sAbrir porta%s           %s2%s  %sFechar porta%s                   %s║%s\n" \
        "$CYAN" "$RESET" "$GREEN"   "$RESET" "$WHITE" "$RESET" "$GREEN"   "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s3%s  %sReiniciar porta%s       %s4%s  %sAlterar status%s                 %s║%s\n" \
        "$CYAN" "$RESET" "$YELLOW"  "$RESET" "$WHITE" "$RESET" "$YELLOW"  "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s5%s  %sConexões por porta%s    %s6%s  %sPortas da máquina%s              %s║%s\n" \
        "$CYAN" "$RESET" "$BLUE"    "$RESET" "$WHITE" "$RESET" "$BLUE"    "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s7%s  %sAtualizar proxy%s       %s8%s  %sGerenciador(htop)%s              %s║%s\n" \
        "$CYAN" "$RESET" "$MAGENTA" "$RESET" "$WHITE" "$RESET" "$BLUE"    "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s9%s  %sMenu SSH%s              %s0%s  %sSair%s                           %s║%s\n" \
        "$CYAN" "$RESET" "$CYAN"    "$RESET" "$WHITE" "$RESET" "$RED"     "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s                                                              %s║%s\n" "$CYAN" "$RESET" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n" "$CYAN" "$RESET"
    echo
}

# ═══════════════════════════════════════════════════════════════
#  Loop principal
# ═══════════════════════════════════════════════════════════════

show_menu() {
    stop_live_header
    clear
    printf "%s" "$CURSOR_HIDE"
    draw_menu
    printf "%s" "$CURSOR_SHOW"
    start_live_header

    prompt "   ${YELLOW}→ Selecione uma opção: ${RESET}" option

    stop_live_header

    case $option in

        1)  # Abrir porta
            clear
            echo
            prompt "  ${CYAN}Porta:${RESET} " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo "${RED}  Porta inválida.${RESET}"
                prompt "  ${CYAN}Porta:${RESET} " port
            done
            prompt "  ${CYAN}Status de conexão (vazio = padrão):${RESET} " status
            add_proxy_port "$port" "$status"
            [ "$port" == "8080" ] && \
                echo "${YELLOW}  ⚠  A porta 80 requer que a 8080 esteja desativada.${RESET}"
            echo "${GREEN}  ✔  Porta ${port} ativada com sucesso.${RESET}"
            pause
            ;;

        2)  # Fechar porta
            clear
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

        3)  # Reiniciar porta
            clear
            echo
            if [ ! -s "$PORTS_FILE" ]; then
                echo "${YELLOW}  ⚠  Nenhuma porta ativa para reiniciar.${RESET}"
                pause
                return
            fi
            echo "  ${DIM}Portas abertas:${RESET}"
            while read -r p; do
                printf "    %s  %s%s%s\n" \
                    "$(get_port_status_symbol "$p")" "$WHITE" "$p" "$RESET"
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

        4)  # Alterar status
            change_port_status
            ;;

        5)  # Conexões por porta
            show_connections
            ;;

        6)  # Portas da máquina
            show_open_ports
            ;;

        7)  # Atualizar
            check_and_update
            ;;

        8)  # htop
            htop
            ;;

        9)  # Menu SSH
            menu
            ;;

        0)  # Sair
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
#  Bootstrap
# ═══════════════════════════════════════════════════════════════

[ ! -f "$PORTS_FILE" ] && sudo touch "$PORTS_FILE"

while true; do
    show_menu
done
