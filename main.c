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
#include <netinet/tcp.h>

/* ------------------------------------------------------------------ */
/* Constantes                                                           */
/* ------------------------------------------------------------------ */
#define BUFFER_SIZE      262144
#define PEEK_TIMEOUT     5
#define CONNECT_TIMEOUT  10
#define MAX_STATUS       32
#define MAX_BACKEND      32
#define MAX_RETRIES      3
#define MAX_REQUESTS     100     /* Máximo de requisições multiplexadas */
#define MAX_ROTATE_HOSTS 32      /* Máximo de hosts para rotação */

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

/* Estrutura para requisição multiplexada */
typedef struct {
    char *raw_request;          /* Request original completo */
    char *method;               /* GET, POST, etc */
    char *path;                 /* /caminho */
    char *host;                 /* Host após rotação */
    char *headers;              /* Headers processados */
    int   content_length;       /* Content-Length se presente */
    int   is_websocket;         /* Flag para WebSocket */
} MultiplexedRequest;

/* Estrutura para rotação de hosts */
typedef struct {
    char *hosts[MAX_ROTATE_HOSTS];
    int   count;
    int   current_index;
} RotatingHosts;

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
static volatile unsigned long total_bytes_transferred = 0;
static volatile unsigned long active_connections = 0;

/* Cache de rotação de hosts por conexão */
static __thread RotatingHosts *thread_host_rotation = NULL;

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
/* Utilitários de string                                               */
/* ------------------------------------------------------------------ */

/* Substitui [crlf] por \r\n */
static char *replace_crlf(const char *input) {
    if (!input) return NULL;
    
    const char *search = "[crlf]";
    const char *replace = "\r\n";
    char *result;
    int count = 0;
    const char *tmp = input;
    
    /* Conta ocorrências */
    while ((tmp = strstr(tmp, search))) {
        count++;
        tmp += strlen(search);
    }
    
    if (count == 0) return strdup(input);
    
    result = malloc(strlen(input) + (count * (strlen(replace) - strlen(search))) + 1);
    if (!result) return NULL;
    
    char *ptr = result;
    tmp = input;
    const char *found;
    
    while ((found = strstr(tmp, search))) {
        memcpy(ptr, tmp, found - tmp);
        ptr += found - tmp;
        memcpy(ptr, replace, strlen(replace));
        ptr += strlen(replace);
        tmp = found + strlen(search);
    }
    strcpy(ptr, tmp);
    
    return result;
}

/* Substitui [lf] por \n */
static char *replace_lf(const char *input) {
    if (!input) return NULL;
    
    const char *search = "[lf]";
    const char *replace = "\n";
    char *result;
    int count = 0;
    const char *tmp = input;
    
    while ((tmp = strstr(tmp, search))) {
        count++;
        tmp += strlen(search);
    }
    
    if (count == 0) return strdup(input);
    
    result = malloc(strlen(input) + (count * (strlen(replace) - strlen(search))) + 1);
    if (!result) return NULL;
    
    char *ptr = result;
    tmp = input;
    const char *found;
    
    while ((found = strstr(tmp, search))) {
        memcpy(ptr, tmp, found - tmp);
        ptr += found - tmp;
        memcpy(ptr, replace, strlen(replace));
        ptr += strlen(replace);
        tmp = found + strlen(search);
    }
    strcpy(ptr, tmp);
    
    return result;
}

/* Extrai host do cabeçalho Host: */
static char *extract_host(const char *headers) {
    const char *host_pattern = "Host:";
    const char *found = strstr(headers, host_pattern);
    if (!found) return NULL;
    
    found += strlen(host_pattern);
    while (*found == ' ' || *found == '\t') found++;
    
    const char *end = found;
    while (*end && *end != '\r' && *end != '\n' && *end != ' ') end++;
    
    if (end == found) return NULL;
    
    char *host = malloc(end - found + 1);
    if (!host) return NULL;
    
    memcpy(host, found, end - found);
    host[end - found] = '\0';
    return host;
}

/* Processa rotação de hosts no formato [rotate=host1;host2;host3] */
static char *process_host_rotation(const char *input, RotatingHosts *rotator) {
    if (!input || !rotator) return strdup(input);
    
    const char *start = strstr(input, "[rotate=");
    if (!start) return strdup(input);
    
    const char *end = strchr(start + 8, ']');
    if (!end) return strdup(input);
    
    /* Extrai lista de hosts */
    char *hosts_list = malloc(end - start - 7);
    if (!hosts_list) return strdup(input);
    
    memcpy(hosts_list, start + 8, end - start - 8);
    hosts_list[end - start - 8] = '\0';
    
    /* Parseia hosts */
    rotator->count = 0;
    char *token = strtok(hosts_list, ";");
    while (token && rotator->count < MAX_ROTATE_HOSTS) {
        rotator->hosts[rotator->count] = strdup(token);
        rotator->count++;
        token = strtok(NULL, ";");
    }
    free(hosts_list);
    
    if (rotator->count == 0) return strdup(input);
    
    /* Seleciona próximo host (round-robin) */
    int idx = __sync_fetch_and_add(&rotator->current_index, 1) % rotator->count;
    char *selected_host = rotator->hosts[idx];
    
    /* Constrói resultado substituindo [rotate=...] pelo host selecionado */
    size_t prefix_len = start - input;
    size_t suffix_len = strlen(end + 1);
    char *result = malloc(prefix_len + strlen(selected_host) + suffix_len + 1);
    if (!result) return strdup(input);
    
    memcpy(result, input, prefix_len);
    strcpy(result + prefix_len, selected_host);
    strcpy(result + prefix_len + strlen(selected_host), end + 1);
    
    return result;
}

/* Processa placeholders especiais */
static char *process_placeholders(const char *input, const char *host, const char *ua) {
    if (!input) return NULL;
    
    char *result = strdup(input);
    if (!result) return NULL;
    
    /* Substitui [host] */
    if (host) {
        char *pos;
        while ((pos = strstr(result, "[host]"))) {
            char *new_result = malloc(strlen(result) - 6 + strlen(host) + 1);
            if (!new_result) break;
            
            memcpy(new_result, result, pos - result);
            strcpy(new_result + (pos - result), host);
            strcpy(new_result + (pos - result) + strlen(host), pos + 6);
            
            free(result);
            result = new_result;
        }
    }
    
    /* Substitui [ua] (User-Agent aleatório) */
    if (ua) {
        char *pos;
        while ((pos = strstr(result, "[ua]"))) {
            char *new_result = malloc(strlen(result) - 4 + strlen(ua) + 1);
            if (!new_result) break;
            
            memcpy(new_result, result, pos - result);
            strcpy(new_result + (pos - result), ua);
            strcpy(new_result + (pos - result) + strlen(ua), pos + 4);
            
            free(result);
            result = new_result;
        }
    }
    
    return result;
}

/* Gera User-Agent aleatório */
static char *generate_random_ua(void) {
    const char *uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
    };
    return strdup(uas[rand() % (sizeof(uas) / sizeof(uas[0]))]);
}

/* ------------------------------------------------------------------ */
/* Processamento de requisições multiplexadas                          */
/* ------------------------------------------------------------------ */

/* Divide payload em múltiplas requisições usando delimitadores */
static char **split_requests(const char *payload, int *count) {
    if (!payload || !count) return NULL;
    
    char **requests = malloc(MAX_REQUESTS * sizeof(char *));
    if (!requests) return NULL;
    
    *count = 0;
    const char *pos = payload;
    const char *next;
    
    while (*pos && *count < MAX_REQUESTS) {
        /* Procura por delimitadores: [split], [instant_split], \r\n\r\n, \n\n */
        const char *split = strstr(pos, "[split]");
        const char *instant = strstr(pos, "[instant_split]");
        const char *crlfcrlf = strstr(pos, "\r\n\r\n");
        const char *lfcrlf = strstr(pos, "\n\n");
        
        /* Encontra o menor delimitador */
        const char *delim = NULL;
        const char *delim_name = NULL;
        size_t delim_len = 0;
        
        if (split) { delim = split; delim_name = "[split]"; delim_len = 7; }
        if (instant && (!delim || instant < delim)) { 
            delim = instant; delim_name = "[instant_split]"; delim_len = 15; 
        }
        if (crlfcrlf && (!delim || crlfcrlf < delim)) { 
            delim = crlfcrlf; delim_name = "\r\n\r\n"; delim_len = 4; 
        }
        if (lfcrlf && (!delim || lfcrlf < delim)) { 
            delim = lfcrlf; delim_name = "\n\n"; delim_len = 2; 
        }
        
        if (!delim) {
            /* Última requisição */
            requests[*count] = strdup(pos);
            (*count)++;
            break;
        }
        
        size_t len = delim - pos;
        requests[*count] = malloc(len + 1);
        if (!requests[*count]) break;
        
        memcpy(requests[*count], pos, len);
        requests[*count][len] = '\0';
        (*count)++;
        
        pos = delim + delim_len;
    }
    
    return requests;
}

/* Processa uma requisição individual */
static MultiplexedRequest *process_request(const char *raw, RotatingHosts *rotator) {
    MultiplexedRequest *req = calloc(1, sizeof(MultiplexedRequest));
    if (!req) return NULL;
    
    req->raw_request = strdup(raw);
    
    /* Substitui placeholders */
    char *processed = process_placeholders(raw, "[host]", "[ua]");
    if (processed) {
        free(req->raw_request);
        req->raw_request = processed;
    }
    
    /* Substitui [crlf] e [lf] */
    char *with_crlf = replace_crlf(req->raw_request);
    if (with_crlf) {
        free(req->raw_request);
        req->raw_request = with_crlf;
    }
    
    char *with_lf = replace_lf(req->raw_request);
    if (with_lf) {
        free(req->raw_request);
        req->raw_request = with_lf;
    }
    
    /* Processa rotação de hosts */
    char *with_rotation = process_host_rotation(req->raw_request, rotator);
    if (with_rotation) {
        free(req->raw_request);
        req->raw_request = with_rotation;
    }
    
    /* Extrai método e path */
    char *line_end = strstr(req->raw_request, "\r\n");
    if (!line_end) line_end = strstr(req->raw_request, "\n");
    
    if (line_end) {
        char *method_end = strchr(req->raw_request, ' ');
        if (method_end && method_end < line_end) {
            req->method = malloc(method_end - req->raw_request + 1);
            memcpy(req->method, req->raw_request, method_end - req->raw_request);
            req->method[method_end - req->raw_request] = '\0';
            
            char *path_start = method_end + 1;
            char *path_end = strchr(path_start, ' ');
            if (path_end && path_end < line_end) {
                req->path = malloc(path_end - path_start + 1);
                memcpy(req->path, path_start, path_end - path_start);
                req->path[path_end - path_start] = '\0';
            }
        }
    }
    
    /* Extrai Host */
    req->host = extract_host(req->raw_request);
    
    /* Verifica se é WebSocket */
    if (strstr(req->raw_request, "Upgrade: websocket") ||
        strstr(req->raw_request, "Upgrade: WebSocket")) {
        req->is_websocket = 1;
    }
    
    /* Extrai Content-Length */
    const char *cl = strstr(req->raw_request, "Content-Length:");
    if (cl) {
        cl += 15;
        while (*cl == ' ' || *cl == '\t') cl++;
        req->content_length = atoi(cl);
    }
    
    return req;
}

/* ------------------------------------------------------------------ */
/* Funções de rede                                                     */
/* ------------------------------------------------------------------ */
static int peek_data(int sock, char *buffer, int len) {
    struct timeval tv = {PEEK_TIMEOUT, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;
    return recv(sock, buffer, len, MSG_PEEK);
}

static void *transfer(void *arg) {
    int *fds = (int *)arg;
    char *buf = malloc(BUFFER_SIZE);
    if (!buf) {
        free(fds);
        return NULL;
    }

    int flags_in = fcntl(fds[0], F_GETFL, 0);
    fcntl(fds[0], F_SETFL, flags_in | O_NONBLOCK);
    int flags_out = fcntl(fds[1], F_GETFL, 0);
    fcntl(fds[1], F_SETFL, flags_out | O_NONBLOCK);

    fd_set readfds;
    struct timeval tv;
    ssize_t bytes, sent;
    unsigned long total = 0;
    int retry_count = 0;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(fds[0], &readfds);
        
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int ready = select(fds[0] + 1, &readfds, NULL, NULL, &tv);
        
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        } else if (ready == 0) {
            retry_count++;
            if (retry_count > MAX_RETRIES) break;
            continue;
        }

        retry_count = 0;

        if (FD_ISSET(fds[0], &readfds)) {
            bytes = read(fds[0], buf, BUFFER_SIZE);
            if (bytes <= 0) {
                if (bytes == 0 || errno != EAGAIN) break;
                continue;
            }

            total += bytes;
            sent = 0;
            
            while (sent < bytes) {
                ssize_t w = write(fds[1], buf + sent, bytes - sent);
                if (w <= 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        usleep(1000);
                        continue;
                    }
                    goto done;
                }
                sent += w;
            }

            if (total % (10 * 1024 * 1024) < (size_t)bytes) {
                fprintf(stderr, "[transfer] %lu MB transferred\n", total / (1024*1024));
            }
        }
    }

done:
    shutdown(fds[1], SHUT_WR);
    __sync_fetch_and_add(&total_bytes_transferred, total);
    
    free(buf);
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

    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

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
/* CORREÇÃO: Handler com suporte a multiplexação                       */
/* ------------------------------------------------------------------ */
static void handle_client(int client_sock) {
    char        buf[BUFFER_SIZE] = {0};
    char        resp[512];
    const char *status = get_random_status();
    int         request_len;
    RotatingHosts rotator = {0};
    char *ua = NULL;
    
    __sync_fetch_and_add(&active_connections, 1);

    /* Lê request completo */
    request_len = recv(client_sock, buf, BUFFER_SIZE - 1, 0);
    if (request_len <= 0) {
        close(client_sock);
        __sync_fetch_and_sub(&active_connections, 1);
        return;
    }
    buf[request_len] = '\0';

    fprintf(stderr, "[client] Request recebido: %d bytes\n", request_len);

    /* Gera User-Agent aleatório para placeholders */
    ua = generate_random_ua();

    /* Detecta proxyc */
    int has_proxyc = (strstr(buf, "proxyc:on") != NULL) ||
                     (strstr(buf, "proxyc: on") != NULL);

    /* Envia respostas iniciais */
    if (has_proxyc) {
        snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
        write(client_sock, resp, strlen(resp));
    } else {
        snprintf(resp, sizeof(resp), "HTTP/1.1 101 %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
        usleep(10000);
        snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
    }

    /* NOVIDADE: Divide payload em múltiplas requisições */
    int req_count = 0;
    char **raw_requests = split_requests(buf, &req_count);
    
    if (req_count > 1) {
        fprintf(stderr, "[multiplex] Detectadas %d requisições multiplexadas\n", req_count);
    }

    /* Processa cada requisição */
    MultiplexedRequest *requests[MAX_REQUESTS] = {0};
    int processed_count = 0;

    for (int i = 0; i < req_count && i < MAX_REQUESTS; i++) {
        if (!raw_requests[i] || strlen(raw_requests[i]) < 5) continue;
        
        /* NOVIDADE: Processa cada requisição individualmente */
        requests[processed_count] = process_request(raw_requests[i], &rotator);
        if (requests[processed_count]) {
            processed_count++;
        }
    }

    /* Se não conseguiu processar requisições, usa o payload original */
    if (processed_count == 0) {
        requests[0] = process_request(buf, &rotator);
        processed_count = 1;
    }

    /* Se ainda não tem requisições, erro */
    if (processed_count == 0 || !requests[0]) {
        fprintf(stderr, "[client] Falha ao processar requisição\n");
        close(client_sock);
        free(ua);
        __sync_fetch_and_sub(&active_connections, 1);
        return;
    }

    /* NOVIDADE: Conecta ao backend (usando host da primeira requisição) */
    const char *backend_host = requests[0]->host ? requests[0]->host : "0.0.0.0";
    BackendRule *backend = detect_backend(buf, request_len);
    
    /* Se o backend for padrão e temos host específico, usa o host */
    if (strcmp(backend->host, "0.0.0.0") == 0 && requests[0]->host) {
        strcpy(backend->host, requests[0]->host);
    }

    fprintf(stderr, "[client] Backend selecionado: %s:%d\n", backend->host, backend->port);

    int server_sock = connect_backend(backend->host, backend->port);
    if (server_sock < 0) {
        fprintf(stderr, "[client] Falha ao conectar ao backend\n");
        for (int i = 0; i < processed_count; i++) {
            free(requests[i]->raw_request);
            free(requests[i]->method);
            free(requests[i]->path);
            free(requests[i]->host);
            free(requests[i]->headers);
            free(requests[i]);
        }
        free(raw_requests);
        close(client_sock);
        free(ua);
        __sync_fetch_and_sub(&active_connections, 1);
        return;
    }

    /* NOVIDADE: Envia todas as requisições processadas */
    for (int i = 0; i < processed_count; i++) {
        if (requests[i]->raw_request) {
            int req_len = strlen(requests[i]->raw_request);
            ssize_t sent = 0;
            
            /* Adiciona delimitador entre requisições se necessário */
            if (i > 0) {
                write(server_sock, "\r\n", 2);
            }
            
            while (sent < req_len) {
                ssize_t w = write(server_sock, 
                                 requests[i]->raw_request + sent, 
                                 req_len - sent);
                if (w <= 0) {
                    fprintf(stderr, "[client] Falha ao enviar request %d ao backend\n", i);
                    goto cleanup;
                }
                sent += w;
            }
            
            fprintf(stderr, "[client] Request %d enviado: %d bytes (host: %s)\n", 
                    i, req_len, requests[i]->host ? requests[i]->host : "default");
            
            /* Se for WebSocket e for a última requisição, mantém conexão aberta */
            if (requests[i]->is_websocket && i == processed_count - 1) {
                fprintf(stderr, "[websocket] Conexão WebSocket detectada, mantendo aberta\n");
            }
        }
    }

    /* Inicia transferência bidirecional */
    pthread_t t1, t2;
    int *c2s = malloc(2 * sizeof(int)); 
    if (!c2s) {
        goto cleanup;
    }
    c2s[0] = client_sock; 
    c2s[1] = server_sock;
    
    int *s2c = malloc(2 * sizeof(int)); 
    if (!s2c) {
        free(c2s);
        goto cleanup;
    }
    s2c[0] = server_sock; 
    s2c[1] = client_sock;

    pthread_create(&t1, NULL, transfer, c2s);
    pthread_create(&t2, NULL, transfer, s2c);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

cleanup:
    /* Limpeza */
    for (int i = 0; i < processed_count; i++) {
        if (requests[i]) {
            free(requests[i]->raw_request);
            free(requests[i]->method);
            free(requests[i]->path);
            free(requests[i]->host);
            free(requests[i]->headers);
            free(requests[i]);
        }
    }
    free(raw_requests);
    free(ua);
    
    /* Limpa rotação de hosts */
    for (int i = 0; i < rotator.count; i++) {
        free(rotator.hosts[i]);
    }

    fprintf(stderr, "[client] Conexão finalizada\n");
    close(client_sock);
    close(server_sock);
    __sync_fetch_and_sub(&active_connections, 1);
}

/* ------------------------------------------------------------------ */
/* accept_loop                                                        */
/* ------------------------------------------------------------------ */
static void accept_loop(int server_sock) {
    struct sockaddr_storage client_addr;
    socklen_t               client_len = sizeof(client_addr);

    while (1) {
        if (reload_flag) {
            reload_flag = 0;
            parse_args(saved_argc, saved_argv);
            printf("[SIGHUP] Configuração recarregada | "
                   "Multi-status: %d | Backends: %d\n",
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

        fprintf(stderr, "[accept] Nova conexão de %s\n", client_ip);

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_sock);
            continue;
        }
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
    if (listen(server_sock, 256) < 0) {
        perror("listen"); return 1;
    }

    printf("=== ProxyC Multiplex ===\n");
    printf("Porta: %d\n", PORT);
    printf("Status: %d configurações\n", CONFIG.status_count);
    printf("Backends: %d configurados\n", CONFIG.backend_count);
    printf("Buffer: %d bytes\n", BUFFER_SIZE);
    printf("Max requests: %d\n", MAX_REQUESTS);
    printf("Max rotate hosts: %d\n", MAX_ROTATE_HOSTS);
    printf("PID: %d\n", getpid());
    printf("Recarregar config: kill -HUP %d\n", getpid());
    printf("=======================\n\n");

    accept_loop(server_sock);

    pthread_rwlock_destroy(&config_lock);
    free_config(&CONFIG);
    close(server_sock);
    return 0;
}
