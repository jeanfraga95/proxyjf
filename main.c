#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>

/* ------------------------------------------------------------------ */
/* Constantes                                                           */
/* ------------------------------------------------------------------ */
#define BUFFER_SIZE      65536
#define PEEK_TIMEOUT     2
#define CONNECT_TIMEOUT  5
#define MAX_STATUS       32
#define MAX_BACKEND      32

/* ------------------------------------------------------------------ */
/* Estruturas                                                           */
/* ------------------------------------------------------------------ */
typedef struct {
    char pattern[64];
    char host[64];
    int  port;
} BackendRule;

typedef struct {
    char       *statuses[MAX_STATUS];
    int         status_count;
    BackendRule backends[MAX_BACKEND];
    int         backend_count;
} ProxyConfig;

/* ------------------------------------------------------------------ */
/* Globals                                                              */
/* ------------------------------------------------------------------ */
static char             *DEFAULT_STATUS = "Switching Protocols";
static int               PORT           = 80;
static ProxyConfig       CONFIG         = {0};

static volatile sig_atomic_t  reload_flag = 0;
static int                    saved_argc  = 0;
static char                 **saved_argv  = NULL;

static pthread_rwlock_t config_lock = PTHREAD_RWLOCK_INITIALIZER;

/* ------------------------------------------------------------------ */
/* Hosts e paths que imitam CDNs/serviços reais — varia fingerprint     */
/* ------------------------------------------------------------------ */
static const char *FAKE_HOSTS[] = {
    "cdn.cloudflare.com",
    "ws.whatsapp.net",
    "edge-chat.facebook.com",
    "gateway.discord.gg",
    "streaming.netflix.com",
};
#define FAKE_HOSTS_COUNT 5

static const char *FAKE_PATHS[] = {
    "/ws",
    "/socket",
    "/realtime",
    "/stream",
    "/connect",
    "/chat",
    "/live",
};
#define FAKE_PATHS_COUNT 7

static const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1 Version/17.0 Mobile Safari/604.1",
    "okhttp/4.11.0",
    "Dalvik/2.1.0 (Linux; U; Android 13; SM-G991B Build/TP1A)",
};
#define USER_AGENTS_COUNT 4

/* ------------------------------------------------------------------ */
/* Gerenciamento de configuração                                        */
/* ------------------------------------------------------------------ */
static void free_config(ProxyConfig *cfg) {
    for (int i = 0; i < cfg->status_count; i++) {
        free(cfg->statuses[i]);
        cfg->statuses[i] = NULL;
    }
    cfg->status_count  = 0;
    cfg->backend_count = 0;
}

static void parse_args(int argc, char *argv[]) {
    ProxyConfig new_cfg        = {0};
    int         new_port       = 80;
    char       *new_def_status = "Switching Protocols";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            new_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--status") == 0 && i + 1 < argc) {
            new_def_status = argv[++i];
        } else if (strcmp(argv[i], "--status-list") == 0 && i + 1 < argc) {
            char *copy  = strdup(argv[++i]);
            char *token = strtok(copy, ",");
            while (token && new_cfg.status_count < MAX_STATUS) {
                new_cfg.statuses[new_cfg.status_count++] = strdup(token);
                token = strtok(NULL, ",");
            }
            free(copy);
        } else if (strcmp(argv[i], "--upgrade") == 0 && i + 1 < argc) {
            char *copy = strdup(argv[++i]);
            char *rule = strtok(copy, ",");
            while (rule && new_cfg.backend_count < MAX_BACKEND) {
                char pattern[64], host[64];
                int  port;
                if (sscanf(rule, "%63[^:]:%63[^:]:%d", pattern, host, &port) == 3) {
                    strcpy(new_cfg.backends[new_cfg.backend_count].pattern, pattern);
                    strcpy(new_cfg.backends[new_cfg.backend_count].host,    host);
                    new_cfg.backends[new_cfg.backend_count++].port = port;
                }
                rule = strtok(NULL, ",");
            }
            free(copy);
        }
    }

    if (new_cfg.backend_count == 0) {
        strcpy(new_cfg.backends[0].pattern, "SSH");
        strcpy(new_cfg.backends[0].host,    "0.0.0.0");
        new_cfg.backends[0].port = 22;
        strcpy(new_cfg.backends[1].pattern, "");
        strcpy(new_cfg.backends[1].host,    "0.0.0.0");
        new_cfg.backends[1].port = 22;
        new_cfg.backend_count = 2;
    }
    if (new_cfg.status_count == 0) {
        new_cfg.statuses[0]  = strdup(new_def_status);
        new_cfg.status_count = 1;
    }

    pthread_rwlock_wrlock(&config_lock);
    free_config(&CONFIG);
    CONFIG         = new_cfg;
    PORT           = new_port;
    DEFAULT_STATUS = new_def_status;
    pthread_rwlock_unlock(&config_lock);
}

/* ------------------------------------------------------------------ */
/* Handlers de sinal                                                    */
/* ------------------------------------------------------------------ */
static void handle_sighup(int sig)  { (void)sig; reload_flag = 1; }
static void handle_sigchld(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* ------------------------------------------------------------------ */
/* Utilitários gerais                                                   */
/* ------------------------------------------------------------------ */
static int peek_data(int sock, char *buffer, int len) {
    struct timeval tv = {PEEK_TIMEOUT, 0};
    fd_set fds;
    FD_ZERO(&fds); FD_SET(sock, &fds);
    if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;
    return recv(sock, buffer, len, MSG_PEEK);
}

static void *transfer(void *arg) {
    int    *fds = (int *)arg;
    char    buf[BUFFER_SIZE];
    ssize_t bytes;
    while ((bytes = read(fds[0], buf, BUFFER_SIZE)) > 0) {
        ssize_t sent = 0;
        while (sent < bytes) {
            ssize_t w = write(fds[1], buf + sent, bytes - sent);
            if (w <= 0) goto done;
            sent += w;
        }
    }
done:
    shutdown(fds[1], SHUT_WR);
    shutdown(fds[0], SHUT_RD);
    free(fds);
    return NULL;
}

static const char *get_random_status(void) {
    pthread_rwlock_rdlock(&config_lock);
    const char *s = CONFIG.statuses[rand() % CONFIG.status_count];
    pthread_rwlock_unlock(&config_lock);
    return s;
}

static BackendRule *detect_backend(const char *data, int len) {
    pthread_rwlock_rdlock(&config_lock);
    int fallback = (CONFIG.backend_count > 1) ? 1 : 0;
    if (len > 0) {
        for (int i = 0; i < CONFIG.backend_count; i++) {
            if (CONFIG.backends[i].pattern[0] &&
                strstr(data, CONFIG.backends[i].pattern)) {
                BackendRule *r = &CONFIG.backends[i];
                pthread_rwlock_unlock(&config_lock);
                return r;
            }
        }
    }
    BackendRule *r = &CONFIG.backends[fallback];
    pthread_rwlock_unlock(&config_lock);
    return r;
}

/* ------------------------------------------------------------------ */
/* connect() ao backend com timeout + IPv4/IPv6 automático             */
/* ------------------------------------------------------------------ */
static int connect_backend(const char *host, int port) {
    struct sockaddr_storage saddr = {0};
    socklen_t saddr_len;
    int family;

    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&saddr;
    struct sockaddr_in  *s4 = (struct sockaddr_in  *)&saddr;

    if (inet_pton(AF_INET6, host, &s6->sin6_addr) == 1) {
        family = AF_INET6; s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port); saddr_len = sizeof(*s6);
    } else if (inet_pton(AF_INET, host, &s4->sin_addr) == 1) {
        family = AF_INET; s4->sin_family = AF_INET;
        s4->sin_port = htons(port); saddr_len = sizeof(*s4);
    } else {
        fprintf(stderr, "[backend] host inválido: '%s'\n", host);
        return -1;
    }

    int sock = socket(family, SOCK_STREAM, 0);
    if (sock < 0) { perror("[backend] socket"); return -1; }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int r = connect(sock, (struct sockaddr *)&saddr, saddr_len);
    if (r < 0 && errno != EINPROGRESS) {
        perror("[backend] connect"); close(sock); return -1;
    }
    if (r != 0) {
        fd_set wfds; struct timeval tv = {CONNECT_TIMEOUT, 0};
        FD_ZERO(&wfds); FD_SET(sock, &wfds);
        if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
            fprintf(stderr, "[backend] timeout %s:%d\n", host, port);
            close(sock); return -1;
        }
        int so_err = 0; socklen_t so_len = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
        if (so_err != 0) { close(sock); return -1; }
    }
    fcntl(sock, F_SETFL, flags);
    return sock;
}

/* ================================================================== */
/*                                                                      */
/*   OFUSCAÇÃO — WebSocket handshake completo (RFC 6455)                */
/*                                                                      */
/*   Por que o 101 trava na operadora e não no Wi-Fi?                  */
/*                                                                      */
/*   Operadoras usam proxies transparentes com DPI que inspecionam:     */
/*     1. Se o request de upgrade tem os headers obrigatórios           */
/*     2. Se o 101 de resposta tem Upgrade + Connection + Accept        */
/*     3. Se os dados após o 101 têm framing WebSocket válido           */
/*                                                                      */
/*   No Wi-Fi você vai direto ao roteador, sem proxy no caminho.        */
/*   Aqui geramos tudo que o DPI espera ver.                            */
/*                                                                      */
/* ================================================================== */

/*
 * Gera Sec-WebSocket-Key aleatória em Base64 (16 bytes → 24 chars).
 * O RFC 6455 §4.1 exige exatamente esse formato.
 */
static void make_ws_key(char *out, size_t out_sz) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char raw[16];
    for (int i = 0; i < 16; i++) raw[i] = (unsigned char)(rand() & 0xFF);

    int j = 0;
    for (int i = 0; i < 15 && j + 4 < (int)out_sz; i += 3) {
        out[j++] = b64[(raw[i]          >> 2) & 0x3F];
        out[j++] = b64[((raw[i]   << 4) | (raw[i+1] >> 4)) & 0x3F];
        out[j++] = b64[((raw[i+1] << 2) | (raw[i+2] >> 6)) & 0x3F];
        out[j++] = b64[  raw[i+2]                           & 0x3F];
    }
    if (j + 4 < (int)out_sz) {
        out[j++] = b64[(raw[15] >> 2) & 0x3F];
        out[j++] = b64[(raw[15] << 4) & 0x30];
        out[j++] = '='; out[j++] = '=';
    }
    out[j] = '\0';
}

/*
 * Lê o request HTTP completo do cliente (até \r\n\r\n),
 * detectando o header "proxyc:" no caminho.
 */
static int consume_http_request(int sock, char *buf, int bufsz) {
    int total = 0;
    while (total < bufsz - 1) {
        ssize_t n = recv(sock, buf + total, 1, 0);
        if (n <= 0) break;
        total++;
        buf[total] = '\0';
        if (total >= 4 && memcmp(buf + total - 4, "\r\n\r\n", 4) == 0) break;
    }
    return (strstr(buf, "proxyc:on") || strstr(buf, "proxyc: on")) ? 1 : 0;
}

/*
 * Envia 101 com todos os headers que o RFC 6455 §4.2.2 exige.
 * DPIs que validam o handshake bloqueiam se Upgrade/Connection/Accept
 * estiverem ausentes.
 *
 * Sec-WebSocket-Accept: valor de 28 chars (tamanho correto do
 * Base64(SHA-1)), único campo que varia — gerado aleatoriamente
 * para evitar fingerprint por valor fixo.
 */
static void send_ws_101(int sock, const char *status) {
    char ws_accept[32];
    make_ws_key(ws_accept, sizeof(ws_accept)); /* chave aleatória como accept */

    char resp[512];
    int len = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "Sec-WebSocket-Protocol: binary\r\n"
        "\r\n",
        status, ws_accept
    );
    write(sock, resp, len);
}

/*
 * Envia 200 com headers que parecem resposta HTTP de recurso estático.
 * ETags e headers variados para evitar fingerprint por header fixo.
 */
static void send_ws_200(int sock, const char *status) {
    static const char *ETAGS[] = {
        "\"a1b2c3d4e5f6\"", "\"7890abcdef01\"",
        "\"deadbeef1234\"", "\"cafe0123babe\""
    };
    char resp[512];
    int len = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Cache-Control: no-store\r\n"
        "ETag: %s\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "\r\n",
        status, ETAGS[rand() % 4]
    );
    write(sock, resp, len);
}

/*
 * Encapsula os primeiros bytes do payload real em um frame WebSocket
 * (opcode 0x02 = binário, sem máscara, como servidor → cliente).
 *
 * Faz os dados após o handshake parecerem tráfego WebSocket para o DPI,
 * em vez de SSH/VPN crus na porta 80. Cobre o caso de DPIs que
 * inspecionam os primeiros bytes após o 101.
 */
static void ws_send_binary_frame(int sock, const unsigned char *payload, size_t plen) {
    unsigned char header[10];
    size_t        hlen;

    header[0] = 0x82; /* FIN=1, opcode=2 (binário) */

    if (plen <= 125) {
        header[1] = (unsigned char)plen; hlen = 2;
    } else if (plen <= 65535) {
        header[1] = 126;
        header[2] = (plen >> 8) & 0xFF;
        header[3] =  plen       & 0xFF;
        hlen = 4;
    } else {
        header[1] = 127;
        for (int i = 0; i < 8; i++)
            header[2+i] = (plen >> (56 - 8*i)) & 0xFF;
        hlen = 10;
    }

    write(sock, header,  hlen);
    write(sock, payload, plen);
}

/*
 * Envia um GET de upgrade falso antes do 101.
 * Alguns proxies transparentes de operadora só deixam passar o 101
 * se viram um GET com headers de upgrade na direção cliente→servidor.
 * Como o proxy aqui está no servidor, "injetamos" esse GET no fluxo
 * para satisfazer inspeções bidirecionais do DPI.
 */
static void send_fake_upgrade_get(int sock, const char *status) {
    (void)status;
    char ws_key[32];
    make_ws_key(ws_key, sizeof(ws_key));

    const char *host = FAKE_HOSTS[rand() % FAKE_HOSTS_COUNT];
    const char *path = FAKE_PATHS[rand() % FAKE_PATHS_COUNT];
    const char *ua   = USER_AGENTS[rand() % USER_AGENTS_COUNT];
    int fake_port    = 1024 + (rand() % 64511);

    char req[1024];
    int len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: binary\r\n"
        "Origin: http://%s:%d\r\n"
        "User-Agent: %s\r\n"
        "Cache-Control: no-cache\r\n"
        "Pragma: no-cache\r\n"
        "\r\n",
        path, host, ws_key, host, fake_port, ua
    );
    write(sock, req, len);
}

/* ------------------------------------------------------------------ */
/* Tratamento do cliente                                                */
/* ------------------------------------------------------------------ */
static void handle_client(int client_sock) {
    char        buf[BUFFER_SIZE] = {0};
    const char *status           = get_random_status();

    /* Lê e consome o request HTTP completo do cliente */
    int has_proxyc = consume_http_request(client_sock, buf, sizeof(buf));

    if (has_proxyc) {
        /*
         * MODO proxyc:on — cliente conhece o protocolo.
         * Duplo 200 com headers variados para o DPI não rejeitar.
         */
        send_ws_200(client_sock, status);
        send_ws_200(client_sock, status);
    } else {
        /*
         * MODO padrão — handshake WebSocket completo:
         *
         *   → Injeta GET de upgrade falso (satisfaz DPI bidirecional)
         *   → Envia 101 com headers RFC 6455 completos
         *   → Aguarda próximos dados do cliente
         *   → Envia 200 para o app VPN sinalizar início do túnel
         */
        send_fake_upgrade_get(client_sock, status); /* satisfaz DPI bidirecional */
        send_ws_101(client_sock, status);           /* 101 com Upgrade+Accept    */

        memset(buf, 0, sizeof(buf));
        if (recv(client_sock, buf, BUFFER_SIZE, 0) <= 0) {
            close(client_sock); return;
        }

        send_ws_200(client_sock, status);           /* sinaliza túnel pronto     */
    }

    /* Detecta o backend pelo primeiro payload (peek sem consumir) */
    char peek_buf[BUFFER_SIZE] = {0};
    int  peeked = peek_data(client_sock, peek_buf, sizeof(peek_buf) - 1);
    BackendRule *backend = detect_backend(peek_buf, peeked);

    int server_sock = connect_backend(backend->host, backend->port);
    if (server_sock < 0) { close(client_sock); return; }

    /*
     * Consome o peek do buffer e encapsula em frame WebSocket binário.
     * Garante que os primeiros bytes do payload real (ex: SSH banner,
     * OpenVPN hello) saiam como frame WS — não como protocolo cru.
     * DPIs que inspecionam payload pós-101 aceitam isso como dados WS.
     */
    if (peeked > 0) {
        unsigned char real_buf[BUFFER_SIZE];
        int rlen = recv(client_sock, (char *)real_buf, peeked, 0);
        if (rlen > 0)
            ws_send_binary_frame(server_sock, real_buf, rlen);
    }

    /* Tunnel bidirecional raw a partir daqui */
    pthread_t t1, t2;
    int *c2s = malloc(2 * sizeof(int)); c2s[0] = client_sock; c2s[1] = server_sock;
    int *s2c = malloc(2 * sizeof(int)); s2c[0] = server_sock; s2c[1] = client_sock;

    pthread_create(&t1, NULL, transfer, c2s);
    pthread_create(&t2, NULL, transfer, s2c);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(client_sock);
    close(server_sock);
}

/* ------------------------------------------------------------------ */
/* accept_loop direto (sem thread wrapper)                             */
/* ------------------------------------------------------------------ */
static void accept_loop(int server_sock) {
    struct sockaddr_storage client_addr;
    socklen_t               client_len = sizeof(client_addr);

    while (1) {
        if (reload_flag) {
            reload_flag = 0;
            parse_args(saved_argc, saved_argv);
            printf("[SIGHUP] Config recarregada | status: %d | backends: %d\n",
                   CONFIG.status_count, CONFIG.backend_count);
        }

        int client_sock = accept(server_sock,
                                 (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno == EINTR) continue;
            perror("accept"); continue;
        }

        char ip[INET6_ADDRSTRLEN] = {0};
        if (client_addr.ss_family == AF_INET6)
            inet_ntop(AF_INET6,
                &((struct sockaddr_in6 *)&client_addr)->sin6_addr, ip, sizeof(ip));
        else
            inet_ntop(AF_INET,
                &((struct sockaddr_in  *)&client_addr)->sin_addr,  ip, sizeof(ip));

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); close(client_sock); continue; }
        if (pid == 0) {
            close(server_sock);
            handle_client(client_sock);
            exit(0);
        }
        close(client_sock);
    }
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
    srand(time(NULL));
    signal(SIGPIPE, SIG_IGN);

    saved_argc = argc; saved_argv = argv;
    parse_args(argc, argv);

    struct sigaction sa_hup  = {0};
    sa_hup.sa_handler = handle_sighup;
    sigaction(SIGHUP, &sa_hup, NULL);

    struct sigaction sa_chld = {0};
    sa_chld.sa_handler = handle_sigchld;
    sa_chld.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa_chld, NULL);

    /* AF_INET6 com IPV6_V6ONLY=0 → aceita IPv4 e IPv6 no mesmo fd */
    int server_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_sock < 0) { perror("socket"); return 1; }

    int opt = 1, v6only = 0;
    setsockopt(server_sock, SOL_SOCKET,   SO_REUSEADDR, &opt,    sizeof(opt));
    setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY,  &v6only, sizeof(v6only));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(PORT);
    addr.sin6_addr   = in6addr_any;

    if (bind(server_sock,   (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind");   return 1; }
    if (listen(server_sock, 256)                                    < 0) { perror("listen"); return 1; }

    printf("ProxyC rodando na porta %d (IPv4+IPv6) | status: %d | backends: %d\n",
           PORT, CONFIG.status_count, CONFIG.backend_count);
    printf("Reload: kill -HUP %d\n", getpid());

    accept_loop(server_sock);

    pthread_rwlock_destroy(&config_lock);
    free_config(&CONFIG);
    close(server_sock);
    return 0;
}
