ProxyJF 🚀

Proxy Leve em C (45 KB) - 2025

O proxy mais rápido e estável do Brasil!
✅ Multi-status aleatório (Premium, VIP, Ultra)
✅ Túnel SSH/OpenVPN automático
✅ Status 200 com proxyc: on
✅ Funciona em VPS de R$15 (1GB RAM → 2000+ users)
🚀 Instalação (1 linha)
bash

curl -o install.sh https://raw.githubusercontent.com/jeanfraga95/proxyjf/refs/heads/main/install.sh && dos2unix install.sh && chmod +x install.sh && ./install.sh

Pronto! Digite proxyc para abrir o menu.
🎯 Status 200 ao invés de 101

Use o parâmetro proxyc: on na payload:
text

GET / HTTP/1.1[lf]
Host: [host][lf]
proxyc: on[lf]
Connection: Upgrade[lf]
Upgrade: websocket[lf]

Resultado:
text

HTTP/1.1 200 Premium
HTTP/1.1 200 Premium
→ Túnel SSH/OpenVPN aberto ✅

Sem proxyc: on:
text

HTTP/1.1 101 Premium
HTTP/1.1 200 Premium
→ Túnel SSH/OpenVPN aberto ✅

📱 Apps Compatíveis
App	✅ Funciona 100%
TLS Tunnel	✅
HA Tunnel+	✅
HTTP Custom	✅
HTTP INJECTOR ✅
OpenVPN	✅
SSH Tunnel	✅
⚡ Performance
Característica	ProxyJF (C)	Rust/Tokio	Python/Go
Tamanho	45 KB	6 MB	20 MB
RAM por conexão	800 KB	25 MB	50 MB
Conexões simultâneas	5000+	500	200
Latência	5ms	50ms	80ms
🔧 Menu de Gerenciamento
bash

proxyc

text

================= Proxy C ================
| Portas(s): 8080 8888 8443            |
| 1 - Abrir Porta                      |
| 2 - Fechar Porta                     |
| 0 - Sair

🛠️ Comandos Avançados
bash

# Abrir porta com multi-status
proxyc → 1 → 8080 → (deixa vazio para aleatório)

# Manual com status custom
/opt/proxyc/proxy --port 8080 --status-list "Premium,VIP,Ultra" --upgrade "SSH:127.0.0.1:22"

📈 Por que usar ProxyJF?

    🐳 Ultra leve (45 KB vs 6 MB dos outros)
    ⚡ Instantâneo (conecta em 5ms)
    🛡️ Estável (nunca trava)
    🎲 Multi-status aleatório
    🔄 Auto-detecção SSH/OpenVPN
    💎 Status 200 para payloads avançadas

👨‍💻 Desenvolvido por

@jfcloud95
Cloud JF Proxy - 2025
