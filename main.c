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

#define BUFFER_SIZE      65536
#define INBUF_SIZE       (BUFFER_SIZE * 8)   /* buffer acumulador */
#define READ_TIMEOUT_MS  3000
#define SPLIT_TIMEOUT_MS 5000                /* tempo extra para o [split] */
#define CONNECT_TIMEOUT  5
#define MAX_STATUS       64
#define MAX_BACKEND      32

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

static char             *DEFAULT_STATUS = "Switching Protocols";
static int               PORT           = 80;
static ProxyConfig       CONFIG         = {0};
static volatile sig_atomic_t reload_flag = 0;
static int                   saved_argc  = 0;
static char                **saved_argv  = NULL;
static pthread_rwlock_t      config_lock = PTHREAD_RWLOCK_INITIALIZER;

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
                char pattern[64], host[64]; int port;
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
        strcpy(new_cfg.backends[0].host,    "127.0.0.1");
        new_cfg.backends[0].port = 22;
        strcpy(new_cfg.backends[1].pattern, "");
        strcpy(new_cfg.backends[1].host,    "127.0.0.1");
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

static void handle_sighup(int sig)  { (void)sig; reload_flag = 1; }
static void handle_sigchld(int sig) { (void)sig; while (waitpid(-1, NULL, WNOHANG) > 0); }

/* ------------------------------------------------------------------ */
/* Aguarda dados no socket com timeout em milissegundos.               */
/* ------------------------------------------------------------------ */
static int wait_readable(int sock, int ms) {
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    return select(sock + 1, &fds, NULL, NULL, &tv);
}

/* ------------------------------------------------------------------ */
/* Encontra o fim do primeiro request HTTP no buffer.                  */
/*                                                                     */
/* Suporta todos os terminadores usados por apps de injeção HTTP:      */
/*   \r\n\r\n  — RFC padrão                                            */
/*   \n\n      — LF simples (ACL, CHECKIN, etc.)                       */
/*   \r\n\n    — misto (algumas ferramentas)                           */
/*                                                                     */
/* Retorna o offset do byte APÓS o terminador, ou -1 se incompleto.   */
/* ------------------------------------------------------------------ */
static int find_request_end(const char *buf, int len) {
    for (int i = 0; i < len; i++) {
        if (buf[i] != '\n') continue;

        /* \n\n */
        if (i + 1 < len && buf[i+1] == '\n')
            return i + 2;

        /* \r\n\r\n — o \n está em i, então o \r está em i-1 */
        if (i >= 1 && buf[i-1] == '\r' &&
            i + 2 < len && buf[i+1] == '\r' && buf[i+2] == '\n')
            return i + 3;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Classificação de um request                                          */
/* ------------------------------------------------------------------ */
typedef enum {
    REQ_UNKNOWN,
    REQ_INTERMEDIATE,    /* GET, ACL, CHECKIN, etc  → 200 OK          */
    REQ_TUNNEL_UPGRADE,  /* tem Upgrade: websocket  → 101             */
    REQ_TUNNEL_OPEN,     /* tem Content-Length huge → 200 + túnel     */
    REQ_PROXYC,          /* tem proxyc:on           → duplo 200+túnel */
} ReqType;

static ReqType classify_request(const char *req, int len) {
    if (len <= 0) return REQ_UNKNOWN;

    /* proxyc:on */
    if (memmem(req, len, "proxyc:on",  9) ||
        memmem(req, len, "proxyc: on", 10))
        return REQ_PROXYC;

    /* Content-Length com valor gigante (≥ 1 bilhão) */
    const char *cl = memmem(req, len, "Content-Length:", 15);
    if (!cl)    cl = memmem(req, len, "content-length:", 15);
    if (cl) {
        long long v = atoll(cl + 15);
        if (v > 1000000000LL) return REQ_TUNNEL_OPEN;
    }

    /* Upgrade: websocket */
    if (memmem(req, len, "Upgrade:",  8) ||
        memmem(req, len, "upgrade:",  8))
        return REQ_TUNNEL_UPGRADE;

    return REQ_INTERMEDIATE;
}

/* ------------------------------------------------------------------ */
static void *transfer(void *arg) {
    int    *fds = (int *)arg;
    char    buf[BUFFER_SIZE];
    ssize_t n;
    while ((n = read(fds[0], buf, BUFFER_SIZE)) > 0) {
        ssize_t s = 0;
        while (s < n) {
            ssize_t w = write(fds[1], buf + s, n - s);
            if (w <= 0) goto done;
            s += w;
        }
    }
done:
    shutdown(fds[1], SHUT_WR);
    shutdown(fds[0], SHUT_RD);
    free(fds);
    return NULL;
}

static BackendRule *detect_backend(const char *data, int len) {
    pthread_rwlock_rdlock(&config_lock);
    int fallback = (CONFIG.backend_count > 1) ? 1 : 0;
    if (len > 0) {
        for (int i = 0; i < CONFIG.backend_count; i++) {
            if (CONFIG.backends[i].pattern[0] &&
                memmem(data, len,
                       CONFIG.backends[i].pattern,
                       strlen(CONFIG.backends[i].pattern))) {
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

static int connect_backend(const char *host, int port) {
    struct sockaddr_storage saddr = {0};
    socklen_t slen; int fam;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&saddr;
    struct sockaddr_in  *s4 = (struct sockaddr_in  *)&saddr;

    if (inet_pton(AF_INET6, host, &s6->sin6_addr) == 1) {
        fam = AF_INET6; s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port); slen = sizeof(*s6);
    } else if (inet_pton(AF_INET, host, &s4->sin_addr) == 1) {
        fam = AF_INET; s4->sin_family = AF_INET;
        s4->sin_port = htons(port); slen = sizeof(*s4);
    } else {
        fprintf(stderr, "[backend] host inválido: %s\n", host);
        return -1;
    }

    int sock = socket(fam, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    int r = connect(sock, (struct sockaddr *)&saddr, slen);
    if (r < 0 && errno != EINPROGRESS) {
        perror("connect"); close(sock); return -1;
    }
    if (r != 0) {
        fd_set w; struct timeval tv = {CONNECT_TIMEOUT, 0};
        FD_ZERO(&w); FD_SET(sock, &w);
        if (select(sock + 1, NULL, &w, NULL, &tv) <= 0) {
            fprintf(stderr, "[backend] timeout %s:%d\n", host, port);
            close(sock); return -1;
        }
        int e = 0; socklen_t el = sizeof(e);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &e, &el);
        if (e) { fprintf(stderr, "[backend] errno=%d %s:%d\n", e, host, port);
                 close(sock); return -1; }
    }
    fcntl(sock, F_SETFL, flags);
    return sock;
}

/* ------------------------------------------------------------------ */
/* handle_client — parser de chunks com janela deslizante              */
/*                                                                     */
/* ALGORITMO:                                                           */
/* 1. Lê dados em chunks para inbuf[] acumulando tudo                  */
/* 2. Para cada request completo encontrado no buffer:                 */
/*    - classifica                                                      */
/*    - envia resposta HTTP correspondente                              */
/*    - se for TUNNEL_OPEN ou PROXYC → abre túnel e sai               */
/* 3. Se buffer esvaziou sem TUNNEL_OPEN, aguarda mais dados           */
/*    (cobre o [split] real do payload)                                */
/*                                                                     */
/* Por que isso funciona e o byte-a-byte não:                          */
/* [instant_split] envia vários requests em um único segmento TCP.     */
/* recv() devolve tudo de uma vez. O parser de fronteira separa cada   */
/* request dentro do buffer sem precisar de chamadas select() extras.  */
/* ------------------------------------------------------------------ */
static void handle_client(int client_sock) {
    static char inbuf[INBUF_SIZE];   /* buffer acumulador  */
    char        resp[256];
    int         inlen     = 0;       /* bytes em inbuf[]   */
    int         proc      = 0;       /* offset já parseado */
    int         req_count = 0;
    int         status_idx = 0;
    int         done      = 0;

    pthread_rwlock_rdlock(&config_lock);
    int scount = CONFIG.status_count;
    pthread_rwlock_unlock(&config_lock);

    memset(inbuf, 0, sizeof(inbuf));

    while (!done) {
        /* ---- Tenta encontrar um request completo no buffer ---- */
        while (proc < inlen) {
            int avail = inlen - proc;
            int end   = find_request_end(inbuf + proc, avail);

            if (end < 0) break;  /* request incompleto — precisa de mais dados */

            /* Temos um request completo: inbuf[proc .. proc+end-1] */
            const char *req    = inbuf + proc;
            int         reqlen = end;
            proc += end;
            req_count++;

            /* Status atual (circular) */
            pthread_rwlock_rdlock(&config_lock);
            const char *status = CONFIG.statuses[status_idx % CONFIG.status_count];
            pthread_rwlock_unlock(&config_lock);
            status_idx++;

            ReqType type = classify_request(req, reqlen);

            /* Log: extrai método */
            char method[16] = "?";
            for (int k = 0; k < reqlen && k < 15; k++) {
                if (req[k] == ' ' || req[k] == '\r' || req[k] == '\n') {
                    method[k] = '\0'; break;
                }
                if (req[k] >= 'A' && req[k] <= 'Z') method[k] = req[k];
                else method[k] = req[k];
            }
            fprintf(stderr, "[req #%d] %-8s type=%d status=\"%s\"\n",
                    req_count, method, type, status);

            switch (type) {

            case REQ_INTERMEDIATE:
            case REQ_UNKNOWN:
                /* GET, ACL, CHECKIN, UNLOCK sem flags especiais → 200 OK */
                snprintf(resp, sizeof(resp),
                         "HTTP/1.1 200 OK %s\r\n\r\n", status);
                if (write(client_sock, resp, strlen(resp)) <= 0)
                    { close(client_sock); return; }
                fprintf(stderr, "[resp] 200 OK (intermediário)\n");
                break;

            case REQ_TUNNEL_UPGRADE:
                /* Upgrade: websocket → 101 Switching Protocols */
                snprintf(resp, sizeof(resp),
                         "HTTP/1.1 101 %s\r\n\r\n", status);
                if (write(client_sock, resp, strlen(resp)) <= 0)
                    { close(client_sock); return; }
                fprintf(stderr, "[resp] 101 Upgrade\n");
                break;

            case REQ_TUNNEL_OPEN:
                /* Content-Length gigante → 200 OK → abre túnel */
                snprintf(resp, sizeof(resp),
                         "HTTP/1.1 200 OK %s\r\n\r\n", status);
                if (write(client_sock, resp, strlen(resp)) <= 0)
                    { close(client_sock); return; }
                fprintf(stderr, "[resp] 200 OK → TÚNEL (%d requests processados)\n",
                        req_count);
                done = 1;
                break;

            case REQ_PROXYC:
                /* proxyc:on → duplo 200 → abre túnel */
                snprintf(resp, sizeof(resp),
                         "HTTP/1.1 200 OK %s\r\n\r\n", status);
                write(client_sock, resp, strlen(resp));
                write(client_sock, resp, strlen(resp));
                fprintf(stderr, "[resp] duplo 200 (proxyc) → TÚNEL\n");
                done = 1;
                break;
            }

            /* Segurança: evita loop infinito sem sinal de túnel */
            if (!done && req_count > scount * 3 + 12) {
                fprintf(stderr, "[loop] limite atingido (%d), encerrando\n",
                        req_count);
                close(client_sock);
                return;
            }
        }

        if (done) break;

        /* ---- Precisa de mais dados ---- */

        /*
         * Compacta o buffer: descarta os bytes já processados.
         * Isso mantém inbuf[] com apenas dados não processados.
         */
        if (proc > 0) {
            memmove(inbuf, inbuf + proc, inlen - proc);
            inlen -= proc;
            proc   = 0;
        }

        if (inlen >= (int)sizeof(inbuf) - 1) {
            fprintf(stderr, "[loop] buffer cheio sem túnel\n");
            close(client_sock);
            return;
        }

        /*
         * Aguarda mais dados.
         * Usa SPLIT_TIMEOUT para cobrir o atraso do [split] real
         * (que é um segmento TCP separado enviado depois).
         */
        int timeout_ms = (req_count == 0) ? READ_TIMEOUT_MS : SPLIT_TIMEOUT_MS;
        if (wait_readable(client_sock, timeout_ms) <= 0) {
            if (req_count == 0) {
                fprintf(stderr, "[loop] timeout sem nenhum request\n");
                close(client_sock);
                return;
            }
            /*
             * Timeout após alguns requests: pode ser que o payload
             * não termine com Content-Length gigante.
             * Tenta abrir o túnel com o que temos.
             */
            fprintf(stderr, "[loop] timeout após %d requests — abrindo túnel\n",
                    req_count);
            done = 1;
            break;
        }

        int n = recv(client_sock, inbuf + inlen,
                     sizeof(inbuf) - inlen - 1, 0);
        if (n <= 0) {
            fprintf(stderr, "[loop] recv=%d errno=%d\n", n, errno);
            close(client_sock);
            return;
        }
        inlen += n;
        inbuf[inlen] = '\0';
        fprintf(stderr, "[recv] +%d bytes (total=%d)\n", n, inlen);
    }

    /* ----------------------------------------------------------------
     * TÚNEL ABERTO
     * Detecta backend via peek (dados SSH/VPN reais).
     * SSH não envia primeiro (espera banner) → timeout normal,
     * fallback = porta 22.
     * ---------------------------------------------------------------- */
    char peek[4096] = {0};
    int  peek_n = 0;
    if (wait_readable(client_sock, 1500) > 0) {
        peek_n = recv(client_sock, peek, sizeof(peek) - 1, MSG_PEEK);
        if (peek_n < 0) peek_n = 0;
    }
    BackendRule *backend = detect_backend(peek, peek_n);
    fprintf(stderr, "[backend] %s:%d (peek=%d bytes)\n",
            backend->host, backend->port, peek_n);

    int server_sock = connect_backend(backend->host, backend->port);
    if (server_sock < 0) { close(client_sock); return; }

    pthread_t t1, t2;
    int *c2s = malloc(2 * sizeof(int));
    int *s2c = malloc(2 * sizeof(int));
    c2s[0] = client_sock; c2s[1] = server_sock;
    s2c[0] = server_sock; s2c[1] = client_sock;
    pthread_create(&t1, NULL, transfer, c2s);
    pthread_create(&t2, NULL, transfer, s2c);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(client_sock);
    close(server_sock);
}

/* ------------------------------------------------------------------ */
static void accept_loop(int server_sock) {
    struct sockaddr_storage ca;
    socklen_t cl = sizeof(ca);
    while (1) {
        if (reload_flag) {
            reload_flag = 0;
            parse_args(saved_argc, saved_argv);
            printf("[SIGHUP] status=%d backends=%d\n",
                   CONFIG.status_count, CONFIG.backend_count);
        }
        int cs = accept(server_sock, (struct sockaddr *)&ca, &cl);
        if (cs < 0) { if (errno == EINTR) continue; perror("accept"); continue; }

        char ip[INET6_ADDRSTRLEN] = {0};
        if (ca.ss_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&ca)->sin6_addr, ip, sizeof(ip));
        else
            inet_ntop(AF_INET,  &((struct sockaddr_in *)&ca)->sin_addr,  ip, sizeof(ip));
        fprintf(stderr, "[+] %s\n", ip);

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); close(cs); continue; }
        if (pid == 0) { close(server_sock); handle_client(cs); exit(0); }
        close(cs);
    }
}

/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
    srand(time(NULL));
    signal(SIGPIPE, SIG_IGN);
    saved_argc = argc; saved_argv = argv;
    parse_args(argc, argv);

    struct sigaction sa = {0};
    sa.sa_handler = handle_sighup;
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = handle_sigchld;
    sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    int ss = socket(AF_INET6, SOCK_STREAM, 0);
    if (ss < 0) { perror("socket"); return 1; }
    int opt = 1, v6 = 0;
    setsockopt(ss, SOL_SOCKET,   SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(ss, IPPROTO_IPV6, IPV6_V6ONLY,  &v6,  sizeof(v6));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(PORT);
    addr.sin6_addr   = in6addr_any;
    if (bind(ss,   (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind");   return 1; }
    if (listen(ss, 256) < 0)                                     { perror("listen"); return 1; }

    printf("ProxyC porta %d | status=%d | backends=%d\n",
           PORT, CONFIG.status_count, CONFIG.backend_count);
    printf("Reload: kill -HUP %d\n", getpid());

    accept_loop(ss);
    pthread_rwlock_destroy(&config_lock);
    free_config(&CONFIG);
    close(ss);
    return 0;
}
