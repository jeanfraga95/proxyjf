#!/bin/bash

# ═══════════════════════════════════════════════════════════════
#  Proxy C — Menu de controle
#  Repositório: https://github.com/jeanfraga95/proxyjf
# ═══════════════════════════════════════════════════════════════

PORTS_FILE="/opt/proxyc/ports"
PROXY_BIN="/opt/proxyc/proxy"
MENU_SELF="$0"   # caminho deste script (para auto-atualização)

REPO_OWNER="jeanfraga95"
REPO_NAME="proxyjf"
GITHUB_API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents"
RAW_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main"

# ── Cores (sintaxe $'\e[' — funciona em printf/read sem -e) ───
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

# ═══════════════════════════════════════════════════════════════
#  Utilitários de sistema
# ═══════════════════════════════════════════════════════════════

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

get_mem_bar() {
    local pct
    pct=$(free -m | awk 'NR==2{printf "%.0f", $3*100/$2}')
    get_color_bar "$pct"
}

get_uptime() {
    uptime -p 2>/dev/null | sed 's/up //' \
        || uptime | awk -F',' '{print $1}' | awk '{print $3,$4}'
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
    local port=$1
    if sudo systemctl is-active --quiet "proxyc${port}.service" 2>/dev/null; then
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
#  Conexões ativas por porta
# ═══════════════════════════════════════════════════════════════

show_connections() {
    clear
    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s  %s%s  Conexões Ativas%s%52s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n" "$CYAN" "$RESET"
    echo

    if [ ! -s "$PORTS_FILE" ]; then
        echo "${YELLOW}  Nenhuma porta aberta.${RESET}"
        echo
        pause
        return
    fi

    local total_conn=0

    while read -r port; do
        # Busca conexões ESTABLISHED na porta (local ou remota)
        # ss -tn mostra: State, Recv-Q, Send-Q, Local, Peer
        local conns
        conns=$(ss -tn state established 2>/dev/null \
                | awk -v p=":${port}" '$4 ~ p || $5 ~ p {print $5}' \
                | sed 's/:[0-9]*$//' \
                | sort -u)

        local count
        count=$(echo "$conns" | grep -c '\S' 2>/dev/null || echo 0)
        total_conn=$(( total_conn + count ))

        local sym
        sym=$(get_port_status_symbol "$port")

        printf "  %s  %s%-6s%s  %s%d usuário(s)%s\n" \
            "$sym" "$WHITE" "[$port]" "$RESET" "$CYAN" "$count" "$RESET"

        if [ -n "$conns" ] && [ "$count" -gt 0 ]; then
            while IFS= read -r ip; do
                [ -z "$ip" ] && continue
                # Tenta resolver hostname (sem bloquear muito tempo)
                local host
                host=$(timeout 1 host "$ip" 2>/dev/null \
                       | awk '/domain name pointer/{print $NF; exit}' \
                       | sed 's/\.$//')
                [ -z "$host" ] && host="$ip"
                printf "       %s→%s  %-20s  %s(%s)%s\n" \
                    "$DIM" "$RESET" "$ip" "$DIM" "$host" "$RESET"
            done <<< "$conns"
        fi
        echo
    done < "$PORTS_FILE"

    printf "  %sTotal de IPs conectados: %s%d%s\n\n" "$DIM" "$WHITE" "$total_conn" "$RESET"
    pause
}

# ═══════════════════════════════════════════════════════════════
#  Verificação e atualização via GitHub API
# ═══════════════════════════════════════════════════════════════

# Retorna o SHA do arquivo no repositório remoto (GitHub API)
github_sha() {
    local filepath=$1   # ex: "main.c" ou "menu.sh"
    local url="${GITHUB_API}/${filepath}"
    local sha

    sha=$(curl -sf "$url" \
          -H "Accept: application/vnd.github.v3+json" \
          | grep '"sha"' | head -1 | awk -F'"' '{print $4}')
    echo "$sha"
}

# Calcula SHA-1 Git de um arquivo local (mesmo algoritmo que o GitHub usa)
# Git usa: "blob <tamanho>\0<conteúdo>" como entrada do sha1
local_git_sha() {
    local file=$1
    [ ! -f "$file" ] && { echo ""; return; }
    local size content hash
    size=$(wc -c < "$file")
    # printf para incluir o byte nulo corretamente
    { printf "blob %s\0" "$size"; cat "$file"; } | sha1sum | awk '{print $1}'
}

check_and_update() {
    clear
    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s  %s%s  Verificar / Atualizar Proxy%s%32s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "" "$CYAN" "$RESET"
    printf "%s╚══════════════════════════════════════════════════════════════╝%s\n\n" "$CYAN" "$RESET"

    # Verificar dependência
    if ! command -v curl &>/dev/null; then
        echo "${RED}  ✗  curl não encontrado. Instale com: apt install curl${RESET}"
        echo
        pause
        return
    fi

    echo "  ${DIM}Consultando repositório...${RESET}"
    echo

    # ── Verificar main.c (binário do proxy) ───────────────────────────────
    local remote_sha_c local_sha_c
    remote_sha_c=$(github_sha "main.c")
    local_sha_c=$(local_git_sha "$PROXY_BIN.c" 2>/dev/null)
    # Fallback: compara SHA do binário compilado (não é o mesmo, mas serve
    # como indicador de versão se guardarmos o SHA da última compilação)
    local sha_cache="/opt/proxyc/.last_sha_main_c"
    local cached_sha_c=""
    [ -f "$sha_cache" ] && cached_sha_c=$(cat "$sha_cache")

    # ── Verificar menu.sh ─────────────────────────────────────────────────
    local remote_sha_menu local_sha_menu
    remote_sha_menu=$(github_sha "menu.sh")
    local_sha_menu=$(local_git_sha "$MENU_SELF")

    # ── Exibir resultado ──────────────────────────────────────────────────
    local update_proxy=0 update_menu=0

    # Proxy (main.c → binário compilado)
    if [ -z "$remote_sha_c" ]; then
        printf "  %s●%s  proxy (main.c)   %s✗ sem conexão com GitHub%s\n" "$RED" "$RESET" "$RED" "$RESET"
    elif [ -z "$cached_sha_c" ] || [ "$remote_sha_c" != "$cached_sha_c" ]; then
        printf "  %s●%s  proxy (main.c)   %s⬆  atualização disponível%s\n" "$YELLOW" "$RESET" "$YELLOW" "$RESET"
        printf "       remoto: %s%.12s%s\n" "$DIM" "$remote_sha_c" "$RESET"
        printf "       local : %s%.12s%s\n\n" "$DIM" "${cached_sha_c:-"(nunca compilado)"}""$RESET"
        update_proxy=1
    else
        printf "  %s●%s  proxy (main.c)   %s✔  já está atualizado%s\n" "$GREEN" "$RESET" "$GREEN" "$RESET"
        printf "       sha: %s%.12s%s\n\n" "$DIM" "$remote_sha_c" "$RESET"
    fi

    # Menu (menu.sh)
    if [ -z "$remote_sha_menu" ]; then
        printf "  %s●%s  menu.sh          %s✗ sem conexão com GitHub%s\n\n" "$RED" "$RESET" "$RED" "$RESET"
    elif [ "$remote_sha_menu" != "$local_sha_menu" ]; then
        printf "  %s●%s  menu.sh          %s⬆  atualização disponível%s\n" "$YELLOW" "$RESET" "$YELLOW" "$RESET"
        printf "       remoto: %s%.12s%s\n" "$DIM" "$remote_sha_menu" "$RESET"
        printf "       local : %s%.12s%s\n\n" "$DIM" "$local_sha_menu" "$RESET"
        update_menu=1
    else
        printf "  %s●%s  menu.sh          %s✔  já está atualizado%s\n\n" "$GREEN" "$RESET" "$GREEN" "$RESET"
        printf "       sha: %s%.12s%s\n\n" "$DIM" "$remote_sha_menu" "$RESET"
    fi

    # ── Nada para atualizar ───────────────────────────────────────────────
    if [ "$update_proxy" -eq 0 ] && [ "$update_menu" -eq 0 ]; then
        echo "  ${GREEN}Tudo atualizado.${RESET}"
        echo
        pause
        return
    fi

    # ── Perguntar se deseja atualizar ─────────────────────────────────────
    prompt "  ${YELLOW}Deseja instalar as atualizações disponíveis? [s/N]:${RESET} " confirm
    [ "${confirm,,}" != "s" ] && { echo; pause; return; }
    echo

    # ── Atualizar proxy (compilar main.c) ─────────────────────────────────
    if [ "$update_proxy" -eq 1 ]; then
        echo "  ${CYAN}▶ Baixando main.c...${RESET}"

        local tmp_c
        tmp_c=$(mktemp /tmp/proxyjf_main_XXXX.c)

        if ! curl -sf "${RAW_URL}/main.c" -o "$tmp_c"; then
            echo "  ${RED}✗  Falha ao baixar main.c${RESET}"
        else
            echo "  ${CYAN}▶ Compilando...${RESET}"

            local tmp_bin
            tmp_bin=$(mktemp /tmp/proxyjf_bin_XXXX)

            if gcc -O2 -pthread "$tmp_c" -o "$tmp_bin" 2>/tmp/proxyjf_gcc_err.txt; then
                sudo cp "$tmp_bin" "$PROXY_BIN"
                sudo chmod +x "$PROXY_BIN"

                # Salvar SHA para referência futura
                sudo mkdir -p /opt/proxyc
                echo "$remote_sha_c" | sudo tee "$sha_cache" > /dev/null

                # Reiniciar todos os serviços do proxy
                echo "  ${CYAN}▶ Reiniciando serviços...${RESET}"
                while read -r port; do
                    sudo systemctl restart "proxyc${port}.service" 2>/dev/null \
                        && printf "    %s✔%s porta %s reiniciada\n" "$GREEN" "$RESET" "$port" \
                        || printf "    %s✗%s porta %s falhou\n"     "$RED"   "$RESET" "$port"
                done < "$PORTS_FILE"

                echo "  ${GREEN}✔  Proxy atualizado com sucesso.${RESET}"
            else
                echo "  ${RED}✗  Falha na compilação:${RESET}"
                cat /tmp/proxyjf_gcc_err.txt | head -20 | sed 's/^/     /'
            fi

            rm -f "$tmp_bin" /tmp/proxyjf_gcc_err.txt
        fi

        rm -f "$tmp_c"
        echo
    fi

    # ── Atualizar menu.sh ─────────────────────────────────────────────────
    if [ "$update_menu" -eq 1 ]; then
        echo "  ${CYAN}▶ Baixando menu.sh...${RESET}"

        local tmp_menu
        tmp_menu=$(mktemp /tmp/proxyjf_menu_XXXX.sh)

        if ! curl -sf "${RAW_URL}/menu.sh" -o "$tmp_menu"; then
            echo "  ${RED}✗  Falha ao baixar menu.sh${RESET}"
            rm -f "$tmp_menu"
        else
            # Validação básica antes de sobrescrever
            if grep -q "#!/bin/bash" "$tmp_menu"; then
                sudo cp "$tmp_menu" "$MENU_SELF"
                sudo chmod +x "$MENU_SELF"
                echo "  ${GREEN}✔  Menu atualizado. Reiniciando...${RESET}"
                rm -f "$tmp_menu"
                sleep 1
                exec "$MENU_SELF"   # relança com a nova versão
            else
                echo "  ${RED}✗  Arquivo baixado parece inválido. Atualização cancelada.${RESET}"
                rm -f "$tmp_menu"
            fi
        fi
        echo
    fi

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
#  Menu principal
# ═══════════════════════════════════════════════════════════════

show_menu() {
    clear

    local cpu_pct mem_info up_time cpu_bar mem_bar
    cpu_pct=$(get_cpu_usage)
    mem_info=$(get_mem_usage)
    up_time=$(get_uptime)
    cpu_bar=$(get_color_bar "$cpu_pct")
    mem_bar=$(get_mem_bar)

    # ── Cabeçalho ─────────────────────────────────────────────────────────
    printf "%s╔══════════════════════════════════════════════════════════════╗%s\n" "$CYAN" "$RESET"
    printf "%s║%s  %s%s  Proxy C  %s%sv1.4%s                 %suptime: %-18s%s%s║%s\n" \
        "$CYAN" "$RESET" "$BOLD" "$WHITE" "$RESET" "$DIM" "$RESET" "$DIM" "$up_time" "$RESET" "$CYAN" "$RESET"
    printf "%s╠══════════════════════════════════════════════════════════════╣%s\n" "$CYAN" "$RESET"

    printf "%s║%s  %sCPU%s  %s  %3s%%   %s║%s\n" \
        "$CYAN" "$RESET" "$DIM" "$RESET" "$cpu_bar" "$cpu_pct" "$CYAN" "$RESET"
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
    printf "%s║%s   %s3%s  %sReiniciar porta%s       %s4%s  %sConexões por porta%s              %s║%s\n" \
        "$CYAN" "$RESET" "$YELLOW"  "$RESET" "$WHITE" "$RESET" "$BLUE"    "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s5%s  %sVerificar atualizações%s %s6%s  %sGerenciador (htop)%s              %s║%s\n" \
        "$CYAN" "$RESET" "$MAGENTA" "$RESET" "$WHITE" "$RESET" "$BLUE"    "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
    printf "%s║%s   %s7%s  %sMenu SSH%s              %s0%s  %sSair%s                           %s║%s\n" \
        "$CYAN" "$RESET" "$CYAN"    "$RESET" "$WHITE" "$RESET" "$RED"     "$RESET" "$WHITE" "$RESET" "$CYAN" "$RESET"
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
                printf "    %s  %s%s%s\n" "$(get_port_status_symbol "$p")" "$WHITE" "$p" "$RESET"
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

        # ── Conexões por porta ────────────────────────────────────────────
        4)
            show_connections
            ;;

        # ── Verificar/atualizar ───────────────────────────────────────────
        5)
            check_and_update
            ;;

        # ── Gerenciador ───────────────────────────────────────────────────
        6)
            htop
            ;;

        # ── Menu SSH ──────────────────────────────────────────────────────
        7)
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

# ═══════════════════════════════════════════════════════════════
#  Bootstrap
# ═══════════════════════════════════════════════════════════════

[ ! -f "$PORTS_FILE" ] && sudo touch "$PORTS_FILE"

while true; do
    show_menu
done
