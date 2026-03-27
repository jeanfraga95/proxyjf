#!/bin/bash

PORTS_FILE="/opt/proxyc/ports"

# Função para verificar se uma porta está em uso
is_port_in_use() {
    local port=$1
    
    if netstat -tuln 2>/dev/null | grep -q ":[0-9]*$port\b"; then
        return 0  
    elif ss -tuln 2>/dev/null | grep -q ":[0-9]*$port\b"; then
        return 0  
    else
        return 1 
    fi
}


# Função para abrir uma porta de proxy
add_proxy_port() {
    local port=$1
    local status=${2:-"C"}

    if is_port_in_use $port; then
        echo "A porta $port já está em uso."
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
    sudo systemctl start "proxyc${port}.service"

    # Salvar a porta no arquivo
    echo $port >> "$PORTS_FILE"
    echo "Porta $port aberta com sucesso."
}

# Função para fechar uma porta de proxy
del_proxy_port() {
    local port=$1

    sudo systemctl disable "proxyc${port}.service"
    sudo systemctl stop "proxyc${port}.service"
    sudo rm -f "/etc/systemd/system/proxyc${port}.service"
    sudo systemctl daemon-reload

    # Remover a porta do arquivo
    sed -i "/^$port$/d" "$PORTS_FILE"
    echo "Porta $port fechada com sucesso."
}

# Função para exibir o menu formatado
show_menu() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}              ${BOLD}${WHITE}Proxy C 1.2${RESET}                            ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${RESET}"
    
    # Verifica se há portas ativas
    if [ ! -s "$PORTS_FILE" ]; then
        printf "| Portas(s): %-34s|\n" "nenhuma"
    else
        active_ports=""
        while read -r port; do
            active_ports+=" $port"
        done < "$PORTS_FILE"
        printf "| Portas(s):%-35s|\n" "$active_ports"
    fi

   echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}              ${BOLD}${WHITE}MENU DE CONTROLE${RESET}                            ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${RESET}"

printf "${CYAN}║${RESET}  ${GREEN}%-2s${RESET}      - %-48s ${CYAN}║${RESET}\n" "1" "Abrir Porta"
printf "${CYAN}║${RESET}  ${GREEN}%-2s${RESET}      - %-48s ${CYAN}║${RESET}\n" "2" "Fechar Porta"
printf "${CYAN}║${RESET}  ${GREEN}%-2s${RESET}      - %-48s ${CYAN}║${RESET}\n" "3" "Abrir Gerenciador"
printf "${CYAN}║${RESET}  ${GREEN}%-2s${RESET}      - %-48s ${CYAN}║${RESET}\n" "4" "Ir para o Menu do script SSH"
printf "${CYAN}║${RESET}  ${GREEN}%-2s${RESET}      - %-48s ${CYAN}║${RESET}\n" "0" "Voltar ao menu anterior"

echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}"
echo
read -p "   ${YELLOW}→ Selecione uma opção: ${RESET}" option

    case $option in
        1)
            read -p "Digite a porta: " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo "Digite uma porta válida."
                read -p "Digite a porta: " port
            done
            
            read -p "Digite o status de conexão (deixe vazio para o padrão): " status
            add_proxy_port $port "$status"
            if [ "$port" == "8080" ]; then
        printf "A Porta 80 para ativar precisa que a porta 8080 esteja desativada\n"
            fi
            read -p "> Porta ativada com sucesso. Pressione qualquer tecla para voltar ao menu." dummy
            ;;
        2)
            read -p "Digite a porta: " port
            while ! [[ $port =~ ^[0-9]+$ ]]; do
                echo "Digite uma porta válida."
                read -p "Digite a porta: " port
                
            done
            del_proxy_port $port
            read -p "> Porta desativada com sucesso. Pressione qualquer tecla para voltar ao menu." dummy
            ;;
        0)
            exit 0
            ;;
        3)
            htop
            ;;
        4)
            menu
            ;;
       
        *)
            echo "Opção inválida. Pressione qualquer tecla para voltar ao menu."
            read -n 1 dummy
            ;;
    esac
}



# Verificar se o arquivo de portas existe, caso contrário, criar 
if [ ! -f "$PORTS_FILE" ]; then
    sudo touch "$PORTS_FILE"
fi

# Loop do menu
while true; do
    show_menu
done
