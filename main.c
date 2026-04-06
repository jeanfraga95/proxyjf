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

/*
 * Lê dados com timeout sem consumir o buffer (MSG_PEEK).
 */
static int peek_data(int sock, char *buffer, int len) {
    struct timeval tv = {PEEK_TIMEOUT, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;
    return recv(sock, buffer, len, MSG_PEEK);
}

/*
 * Consome (descarta) todos os dados disponíveis até o fim dos headers HTTP
 * (sequência "\r\n\r\n"), sem bloquear mais que PEEK_TIMEOUT segundos.
 * Retorna o número total de bytes consumidos.
 */
static int drain_http_request(int sock) {
    char           buf[BUFFER_SIZE];
    int            total = 0;
    struct timeval tv;
    fd_set         fds;

    while (1) {
        tv.tv_sec  = PEEK_TIMEOUT;
        tv.tv_usec = 0;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) break;

        ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        total += (int)n;

        /* Para quando encontrar o fim dos headers */
        if (strstr(buf, "\r\n\r\n")) break;
    }
    return total;
}

/*
 * Transfere fds[0] → fds[1] em loop tratando writes parciais.
 */
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

    if (len <= 0) {
        BackendRule *r = &CONFIG.backends[fallback];
        pthread_rwlock_unlock(&config_lock);
        return r;
    }
    for (int i = 0; i < CONFIG.backend_count; i++) {
        if (CONFIG.backends[i].pattern[0] &&
            strstr(data, CONFIG.backends[i].pattern))
        {
            BackendRule *r = &CONFIG.backends[i];
            pthread_rwlock_unlock(&config_lock);
            return r;
        }
    }
    BackendRule *r = &CONFIG.backends[fallback];
    pthread_rwlock_unlock(&config_lock);
    return r;
}

/* ------------------------------------------------------------------ */
/* connect() ao backend com timeout + suporte IPv4/IPv6                */
/* ------------------------------------------------------------------ */
static int connect_backend(const char *host, int port) {
    struct sockaddr_storage saddr    = {0};
    socklen_t               saddr_len;
    int                     family;

    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&saddr;
    struct sockaddr_in  *s4 = (struct sockaddr_in  *)&saddr;

    if (inet_pton(AF_INET6, host, &s6->sin6_addr) == 1) {
        family          = AF_INET6;
        s6->sin6_family = AF_INET6;
        s6->sin6_port   = htons(port);
        saddr_len       = sizeof(struct sockaddr_in6);
    } else if (inet_pton(AF_INET, host, &s4->sin_addr) == 1) {
        family         = AF_INET;
        s4->sin_family = AF_INET;
        s4->sin_port   = htons(port);
        saddr_len      = sizeof(struct sockaddr_in);
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
        perror("[backend] connect");
        close(sock);
        return -1;
    }

    if (r != 0) {
        fd_set         wfds;
        struct timeval tv = {CONNECT_TIMEOUT, 0};
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);

        int sel = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (sel <= 0) {
            fprintf(stderr, "[backend] timeout conectando em %s:%d\n", host, port);
            close(sock);
            return -1;
        }

        int       so_err = 0;
        socklen_t so_len = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
        if (so_err != 0) {
            fprintf(stderr, "[backend] falha ao conectar em %s:%d — errno %d\n",
                    host, port, so_err);
            close(sock);
            return -1;
        }
    }

    fcntl(sock, F_SETFL, flags);
    return sock;
}

/* ------------------------------------------------------------------ */
/* Detecção do tipo de requisição recebida                              */
/* ------------------------------------------------------------------ */

/*
 * Retorna 1 se o buffer contém os marcadores do padrão multi-split:
 *   - um método GET ou UNLOCK
 *   - presença de "Upgrade:" ou "Content-Length:" gigante
 *   - presença do segundo UNLOCK (3ª requisição da cadeia)
 *
 * O [split] nas ferramentas de injeção significa que o cliente envia
 * os segmentos em pacotes separados, mas o proxy os recebe em sequência
 * no mesmo socket — basta tratá-los como requests consecutivos.
 */
static int is_multi_split_request(const char *buf) {
    return (strstr(buf, "GET ")    != NULL ||
            strstr(buf, "UNLOCK ") != NULL) &&
           (strstr(buf, "Upgrade:") != NULL ||
            strstr(buf, "upgrade:") != NULL);
}

/* ------------------------------------------------------------------ */
/* Tratamento do cliente — com suporte ao padrão multi-split           */
/* ------------------------------------------------------------------ */

/*
 * Fluxo do padrão multi-split (ex: HTTP Injector / NapsternetV):
 *
 *  Cliente → Proxy:  GET /cdn-cgi/trace HTTP/1.1 ...
 *  Proxy   → Cliente: HTTP/1.1 200 OK <status>\r\n\r\n
 *
 *  Cliente → Proxy:  UNLOCK /? HTTP/1.1 ... Upgrade: websocket ...
 *  Proxy   → Cliente: HTTP/1.1 101 <status>\r\n\r\n
 *
 *  Cliente → Proxy:  UNLOCK /? HTTP/1.1 ... Content-Length: 9999999999999 ...
 *  Proxy   → Cliente: HTTP/1.1 200 OK <status>\r\n\r\n
 *
 *  [ túnel bidirecional estabelecido ]
 */
static void handle_client(int client_sock) {
    char        buf[BUFFER_SIZE] = {0};
    char        resp[512];
    const char *status;

    /* ---- Peek inicial para classificar a requisição ---- */
    int peeked = peek_data(client_sock, buf, sizeof(buf) - 1);
    buf[peeked > 0 ? peeked : 0] = '\0';

    int  is_multi  = is_multi_split_request(buf);
    int  has_proxyc = (strstr(buf, "proxyc:on")  != NULL) ||
                      (strstr(buf, "proxyc: on") != NULL);

    if (is_multi) {
        /* ============================================================
         * MODO MULTI-SPLIT (GET → UNLOCK+Upgrade → UNLOCK+Content-Length)
         * ============================================================ */

        /* --- Segmento 1: GET (ex: /cdn-cgi/trace) → 200 OK --- */
        status = get_random_status();
        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 200 OK %s\r\n"
                 "Content-Length: 0\r\n"
                 "Connection: keep-alive\r\n\r\n",
                 status);
        if (write(client_sock, resp, strlen(resp)) <= 0) {
            close(client_sock); return;
        }
        drain_http_request(client_sock);   /* descarta o GET */

        /* --- Segmento 2: UNLOCK + Upgrade: websocket → 101 --- */
        memset(buf, 0, sizeof(buf));
        peeked = peek_data(client_sock, buf, sizeof(buf) - 1);
        if (peeked <= 0) { close(client_sock); return; }

        status = get_random_status();
        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 101 %s\r\n"
                 "Connection: Upgrade\r\n"
                 "Upgrade: websocket\r\n\r\n",
                 status);
        if (write(client_sock, resp, strlen(resp)) <= 0) {
            close(client_sock); return;
        }
        drain_http_request(client_sock);   /* descarta o UNLOCK de upgrade */

        /* --- Segmento 3: UNLOCK + Content-Length gigante → 200 --- */
        memset(buf, 0, sizeof(buf));
        peeked = peek_data(client_sock, buf, sizeof(buf) - 1);
        if (peeked <= 0) { close(client_sock); return; }

        status = get_random_status();
        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 200 OK %s\r\n"
                 "Content-Length: 0\r\n\r\n",
                 status);
        if (write(client_sock, resp, strlen(resp)) <= 0) {
            close(client_sock); return;
        }
        drain_http_request(client_sock);   /* descarta o UNLOCK de túnel */

    } else if (has_proxyc) {
        /* ============================================================
         * MODO proxyc:on → duplo 200
         * ============================================================ */
        status = get_random_status();
        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 200 OK %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
        write(client_sock, resp, strlen(resp));
        if (recv(client_sock, buf, BUFFER_SIZE, 0) <= 0) {
            close(client_sock); return;
        }

    } else {
        /* ============================================================
         * MODO PADRÃO → 101 + consumir + 200
         * ============================================================ */
        status = get_random_status();
        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 101 %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
        if (recv(client_sock, buf, BUFFER_SIZE, 0) <= 0) {
            close(client_sock); return;
        }
        status = get_random_status();
        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 200 OK %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
    }

    /* ---- Peek do payload real para escolher o backend ---- */
    char peek[BUFFER_SIZE] = {0};
    int  peek_n = peek_data(client_sock, peek, sizeof(peek) - 1);
    BackendRule *backend = detect_backend(peek, peek_n);

    int server_sock = connect_backend(backend->host, backend->port);
    if (server_sock < 0) { close(client_sock); return; }

    /* ---- Túnel bidirecional ---- */
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
            printf("[SIGHUP] Config recarregada | status: %d | backends: %d\n",
                   CONFIG.status_count, CONFIG.backend_count);
        }

        int client_sock = accept(server_sock,
                                 (struct sockaddr *)&client_addr,
                                 &client_len);
        if (client_sock < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        char client_ip[INET6_ADDRSTRLEN] = {0};
        if (client_addr.ss_family == AF_INET6) {
            inet_ntop(AF_INET6,
                      &((struct sockaddr_in6 *)&client_addr)->sin6_addr,
                      client_ip, sizeof(client_ip));
        } else {
            inet_ntop(AF_INET,
                      &((struct sockaddr_in *)&client_addr)->sin_addr,
                      client_ip, sizeof(client_ip));
        }
        printf("[+] conexão de %s\n", client_ip);

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
    setsockopt(server_sock, SOL_SOCKET,   SO_REUSEADDR,  &opt,  sizeof(opt));
    int v6only = 0;
    setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY,   &v6only, sizeof(v6only));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(PORT);
    addr.sin6_addr   = in6addr_any;

    if (bind(server_sock,   (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind");   return 1; }
    if (listen(server_sock, 256)                                     < 0) { perror("listen"); return 1; }

    printf("ProxyC porta %d (IPv4+IPv6) | status: %d | backends: %d\n",
           PORT, CONFIG.status_count, CONFIG.backend_count);
    printf("Reload: kill -HUP %d\n", getpid());

    accept_loop(server_sock);

    pthread_rwlock_destroy(&config_lock);
    free_config(&CONFIG);
    close(server_sock);
    return 0;
}