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
#define PEEK_SIZE        8192    /* tamanho do peek inicial             */
#define PEEK_TIMEOUT     5
#define CONNECT_TIMEOUT  10
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

static volatile sig_atomic_t  reload_flag  = 0;
static int                    saved_argc   = 0;
static char                 **saved_argv   = NULL;

static pthread_rwlock_t config_lock = PTHREAD_RWLOCK_INITIALIZER;

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
        new_cfg.statuses[0]   = strdup(new_def_status);
        new_cfg.status_count  = 1;
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
static void handle_sighup(int sig) {
    (void)sig;
    reload_flag = 1;
}

static void handle_sigchld(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* ------------------------------------------------------------------ */
/* Utilitários de rede                                                  */
/* ------------------------------------------------------------------ */

/* Peek sem consumir */
static int peek_data(int sock, char *buffer, int len) {
    struct timeval tv = {PEEK_TIMEOUT, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;
    return recv(sock, buffer, len, MSG_PEEK);
}

/* Lê com timeout sem bloquear indefinidamente */
static ssize_t recv_timeout(int sock, char *buf, int len, int timeout_sec) {
    struct timeval tv = {timeout_sec, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;
    return recv(sock, buf, len, 0);
}

/* Thread de transferência bidirecional */
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
/* connect_backend com timeout e IPv4/IPv6                             */
/* ------------------------------------------------------------------ */
static int connect_backend(const char *host, int port) {
    struct sockaddr_storage saddr = {0};
    socklen_t saddr_len;
    int       family;

    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&saddr;
    struct sockaddr_in  *s4 = (struct sockaddr_in  *)&saddr;

    if (inet_pton(AF_INET6, host, &s6->sin6_addr) == 1) {
        family = AF_INET6;
        s6->sin6_family = AF_INET6;
        s6->sin6_port   = htons(port);
        saddr_len = sizeof(struct sockaddr_in6);
    } else if (inet_pton(AF_INET, host, &s4->sin_addr) == 1) {
        family = AF_INET;
        s4->sin_family = AF_INET;
        s4->sin_port   = htons(port);
        saddr_len = sizeof(struct sockaddr_in);
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
        fd_set wfds;
        struct timeval tv = {CONNECT_TIMEOUT, 0};
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
            fprintf(stderr, "[backend] timeout %s:%d\n", host, port);
            close(sock); return -1;
        }
        int so_err = 0; socklen_t so_len = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
        if (so_err) {
            fprintf(stderr, "[backend] erro %s:%d errno=%d\n", host, port, so_err);
            close(sock); return -1;
        }
    }
    fcntl(sock, F_SETFL, flags);
    return sock;
}

/* ------------------------------------------------------------------ */
/* Análise do payload HTTP                                              */
/* ------------------------------------------------------------------ */

static const char *HTTP_VERBS[] = {
    "GET ", "POST ", "HEAD ", "OPTIONS ", "CONNECT ",
    "ACL ", "CHECKIN ", "UNLOCK ", "PROPFIND ", "SUBSCRIBE ",
    "PROPPATCH ", "MKCOL ", "COPY ", "MOVE ", "LOCK ",
    NULL
};

/*
 * Conta quantos verbos HTTP aparecem no buffer.
 * Retorna também, via *first_verb_end, o ponteiro para logo após
 * o fim do PRIMEIRO bloco HTTP (fim do \r\n\r\n ou \n\n).
 */
static int analyze_request(const char *buf, int len,
                            int *first_end_off,  /* offset do fim do 1º bloco */
                            int *total_http_end) /* offset do fim de todos os blocos HTTP */
{
    int verb_count = 0;
    *first_end_off  = -1;
    *total_http_end = -1;

    const char *p   = buf;
    const char *end = buf + len;
    int last_block_end = 0;

    while (p < end) {
        /* Verifica se começa um verbo HTTP nesta posição */
        int found = 0;
        for (int v = 0; HTTP_VERBS[v]; v++) {
            size_t vlen = strlen(HTTP_VERBS[v]);
            if ((size_t)(end - p) >= vlen && memcmp(p, HTTP_VERBS[v], vlen) == 0) {
                verb_count++;
                found = 1;
                /* Avança até o fim deste bloco HTTP (\r\n\r\n ou \n\n) */
                const char *block = p;
                while (block < end - 1) {
                    if (block[0] == '\r' && block[1] == '\n' &&
                        block + 3 < end &&
                        block[2] == '\r' && block[3] == '\n') {
                        int off = (int)(block - buf) + 4;
                        if (verb_count == 1) *first_end_off = off;
                        last_block_end = off;
                        p = buf + off;
                        goto next_verb;
                    }
                    if (block[0] == '\n' && block[1] == '\n') {
                        int off = (int)(block - buf) + 2;
                        if (verb_count == 1) *first_end_off = off;
                        last_block_end = off;
                        p = buf + off;
                        goto next_verb;
                    }
                    block++;
                }
                /* Bloco sem terminador — avança até o fim */
                p = end;
                goto next_verb;
            }
        }
        if (!found) p++;
        continue;
next_verb:;
    }

    *total_http_end = last_block_end > 0 ? last_block_end : len;
    return verb_count;
}

/* ------------------------------------------------------------------ */
/* Lê e descarta exatamente `n` bytes do socket                        */
/* ------------------------------------------------------------------ */
static void consume_bytes(int sock, int n) {
    char tmp[4096];
    while (n > 0) {
        int chunk = n > (int)sizeof(tmp) ? (int)sizeof(tmp) : n;
        struct timeval tv = {2, 0};
        fd_set fds;
        FD_ZERO(&fds); FD_SET(sock, &fds);
        if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) break;
        ssize_t r = recv(sock, tmp, chunk, 0);
        if (r <= 0) break;
        n -= (int)r;
    }
}

/* ------------------------------------------------------------------ */
/* Tratamento do cliente                                                */
/* ------------------------------------------------------------------ */
static void handle_client(int client_sock) {
    char        buf[PEEK_SIZE] = {0};
    char        resp[256];

    /* ── 1. Peek do payload completo ──────────────────────────────── */
    int peeked = peek_data(client_sock, buf, sizeof(buf) - 1);
    buf[peeked > 0 ? peeked : 0] = '\0';

    int has_proxyc = (strstr(buf, "proxyc:on")  != NULL) ||
                     (strstr(buf, "proxyc: on") != NULL);

    int first_end  = -1;
    int total_end  = -1;
    int verb_count = analyze_request(buf, peeked, &first_end, &total_end);

    fprintf(stderr, "[client fd=%d] verbos=%d first_end=%d total_end=%d peeked=%d proxyc=%d\n",
            client_sock, verb_count, first_end, total_end, peeked, has_proxyc);

    /* ── 2. Seleciona backend ANTES de consumir dados ─────────────── */
    /*    (usa o payload que ainda está no buffer de peek)             */
    BackendRule *backend = detect_backend(buf, peeked);

    /* ── 3. Handshake HTTP ────────────────────────────────────────── */

    if (has_proxyc) {
        /* Modo proxyc:on → 200 duplo */
        snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK %s\r\n\r\n", get_random_status());
        write(client_sock, resp, strlen(resp));
        write(client_sock, resp, strlen(resp));
        /* Consome o request */
        recv_timeout(client_sock, buf, PEEK_SIZE, 3);

    } else if (verb_count > 1) {
        /*
         * Modo multi-status:
         *   → envia 1 resposta 101 por verbo HTTP encontrado
         *   → consome todos os blocos HTTP do payload
         *   → envia 200 OK para sinalizar que o túnel está pronto
         *
         * O dado após o último bloco HTTP (payload VPN/SSH real)
         * NÃO é consumido — fica no socket para o transfer() usar.
         */
        for (int i = 0; i < verb_count; i++) {
            snprintf(resp, sizeof(resp),
                     "HTTP/1.1 101 %s\r\n\r\n", get_random_status());
            if (write(client_sock, resp, strlen(resp)) < 0) {
                close(client_sock); return;
            }
        }

        /*
         * Consome somente os bytes dos blocos HTTP (total_end bytes).
         * Se total_end == peeked, tudo o que foi "peekado" eram headers
         * e não sobrou payload — normal, o cliente enviará os dados VPN
         * depois do 200.
         * Se total_end < peeked, há bytes extras que não fazem parte dos
         * headers HTTP: NÃO os consumimos.
         */
        if (total_end > 0) {
            consume_bytes(client_sock, total_end);
        }

        /* 200 — túnel pronto */
        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 200 OK %s\r\n\r\n", get_random_status());
        if (write(client_sock, resp, strlen(resp)) < 0) {
            close(client_sock); return;
        }

    } else {
        /* Modo padrão: 101 → consome request → 200 */
        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 101 %s\r\n\r\n", get_random_status());
        write(client_sock, resp, strlen(resp));

        /* Consome o único request */
        int consume = (first_end > 0) ? first_end : peeked;
        if (consume > 0) consume_bytes(client_sock, consume);
        else recv_timeout(client_sock, buf, PEEK_SIZE, 3);

        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 200 OK %s\r\n\r\n", get_random_status());
        write(client_sock, resp, strlen(resp));
    }

    /* ── 4. Conecta ao backend e inicia tunnel ─────────────────────── */
    int server_sock = connect_backend(backend->host, backend->port);
    if (server_sock < 0) {
        fprintf(stderr, "[client fd=%d] falha ao conectar backend\n", client_sock);
        close(client_sock);
        return;
    }

    fprintf(stderr, "[client fd=%d] tunnel → %s:%d\n",
            client_sock, backend->host, backend->port);

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
/* accept_loop                                                          */
/* ------------------------------------------------------------------ */
static void accept_loop(int server_sock) {
    struct sockaddr_storage client_addr;
    socklen_t               client_len = sizeof(client_addr);

    while (1) {
        if (reload_flag) {
            reload_flag = 0;
            parse_args(saved_argc, saved_argv);
            printf("[SIGHUP] config recarregada | statuses=%d backends=%d\n",
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
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&client_addr)->sin6_addr,
                      ip, sizeof(ip));
        else
            inet_ntop(AF_INET, &((struct sockaddr_in*)&client_addr)->sin_addr,
                      ip, sizeof(ip));

        fprintf(stderr, "[accept] %s\n", ip);

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

    saved_argc = argc;
    saved_argv = argv;
    parse_args(argc, argv);

    struct sigaction sa_hup = {0};
    sa_hup.sa_handler = handle_sighup;
    sigaction(SIGHUP, &sa_hup, NULL);

    struct sigaction sa_chld = {0};
    sa_chld.sa_handler = handle_sigchld;
    sa_chld.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa_chld, NULL);

    int server_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_sock < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int v6only = 0;
    setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(PORT);
    addr.sin6_addr   = in6addr_any;

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_sock, 256) < 0) { perror("listen"); return 1; }

    printf("ProxyC porta=%d (IPv4+IPv6) statuses=%d backends=%d\n",
           PORT, CONFIG.status_count, CONFIG.backend_count);
    printf("Reload: kill -HUP %d\n", getpid());

    accept_loop(server_sock);

    pthread_rwlock_destroy(&config_lock);
    free_config(&CONFIG);
    close(server_sock);
    return 0;
}
