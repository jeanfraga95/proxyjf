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
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Constantes                                                           */
/* ------------------------------------------------------------------ */
#define BUFFER_SIZE      65536
#define PEEK_TIMEOUT     1
#define CONNECT_TIMEOUT  5
#define MAX_STATUS       32
#define MAX_BACKEND      32
#define MAX_REQUESTS 32

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
/* Protótipos                                                           */
/* ------------------------------------------------------------------ */
static void         handle_client(int client_sock);
static const char  *generate_websocket_accept(const char *key);
static void         base64_encode(const unsigned char *data, size_t len, char *out);
static void         SHA1(const unsigned char *input, size_t len, unsigned char output[20]);
static BackendRule *detect_backend(const char *data, int len);
static int          connect_backend(const char *host, int port);
static void        *transfer(void *arg);

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
static int peek_data(int sock, char *buffer, int len) {
    struct timeval tv = {PEEK_TIMEOUT, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
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
/* Função principal de tratamento do cliente                            */
/* ------------------------------------------------------------------ */
/* Funções auxiliares para parsing */
static int parse_content_length(const char *data, size_t len) {
    const char *cl = strstr(data, "Content-Length:");
    if (!cl) {
        cl = strstr(data, "Content-length:");
        if (!cl) return -1;
    }
    
    cl += 15; // Pula "Content-Length:"
    while (*cl == ' ' || *cl == '\t') cl++;
    
    char *end = strstr(cl, "\r\n");
    if (!end) end = strstr(cl, "\n");
    if (!end) return -1;
    
    char temp[32] = {0};
    size_t copy_len = (end - cl) < 31 ? (end - cl) : 31;
    strncpy(temp, cl, copy_len);
    
    long long val = strtoll(temp, NULL, 10);
    if (val > INT_MAX) return INT_MAX;
    return (int)val;
}

static char* find_headers_end(const char *data, size_t len) {
    char *end = strstr(data, "\r\n\r\n");
    if (end) return end + 4;
    
    end = strstr(data, "\n\n");
    if (end) return end + 2;
    
    return NULL;
}

static int is_request_complete(const char *data, size_t len) {
    if (len < 4) return 0;
    
    char *headers_end = find_headers_end(data, len);
    if (!headers_end) return 0;
    
    int content_len = parse_content_length(data, len);
    
    if (content_len > 0) {
        size_t body_start = (size_t)(headers_end - data);
        size_t total_needed = body_start + content_len;
        return (len >= total_needed);
    }
    
    return 1;
}

/* Estrutura para armazenar requisição */
typedef struct {
    char *data;
    size_t length;
    size_t offset;
    int is_complete;
    int content_length;
    char method[32];
    char host[256];
    char path[512];
    int is_websocket;
    int has_proxyc;
} HttpRequest;

/* Divide o buffer em requisições individuais */
static int split_requests(char *buffer, size_t len, HttpRequest *requests, int max_requests) {
    int count = 0;
    size_t offset = 0;
    
    while (offset < len && count < max_requests) {
        char *remaining = buffer + offset;
        size_t remaining_len = len - offset;
        
        // Pula linhas vazias iniciais
        while (remaining_len > 0 && (*remaining == '\r' || *remaining == '\n')) {
            remaining++;
            offset++;
            remaining_len--;
        }
        
        if (remaining_len < 4) break;
        
        // Encontra o método HTTP
        char *method_end = strstr(remaining, " ");
        if (!method_end) break;
        
        size_t method_len = method_end - remaining;
        if (method_len >= sizeof(requests[count].method) - 1) break;
        
        strncpy(requests[count].method, remaining, method_len);
        requests[count].method[method_len] = '\0';
        
        // Encontra fim dos headers
        char *headers_end = find_headers_end(remaining, remaining_len);
        if (!headers_end) break;
        
        size_t headers_len = headers_end - remaining;
        
        // Extrai Host
        char *host_start = strstr(remaining, "Host:");
        if (host_start && host_start < headers_end) {
            host_start += 5;
            while (*host_start == ' ' || *host_start == '\t') host_start++;
            char *host_end = strstr(host_start, "\r\n");
            if (!host_end) host_end = strstr(host_start, "\n");
            if (host_end && host_end < headers_end) {
                size_t host_len = host_end - host_start;
                if (host_len < sizeof(requests[count].host) - 1) {
                    strncpy(requests[count].host, host_start, host_len);
                    requests[count].host[host_len] = '\0';
                }
            }
        }
        
        // Extrai Path
        char *path_start = method_end + 1;
        char *path_end = strstr(path_start, " HTTP/");
        if (!path_end) path_end = strstr(path_start, " ");
        if (path_end && path_end < headers_end) {
            size_t path_len = path_end - path_start;
            if (path_len < sizeof(requests[count].path) - 1) {
                strncpy(requests[count].path, path_start, path_len);
                requests[count].path[path_len] = '\0';
            }
        }
        
        // Detecta WebSocket
        requests[count].is_websocket = (strstr(remaining, "Upgrade: websocket") != NULL ||
                                        strstr(remaining, "Upgrade: WebSocket") != NULL);
        
        // Detecta proxyc:on
        requests[count].has_proxyc = (strstr(remaining, "proxyc:on") != NULL ||
                                      strstr(remaining, "proxyc: on") != NULL);
        
        // Content-Length
        int content_len = parse_content_length(remaining, remaining_len);
        requests[count].content_length = content_len;
        
        // Determina tamanho total da requisição
        size_t total_size;
        if (content_len > 0) {
            size_t body_start = headers_len;
            total_size = headers_len + content_len;
            requests[count].is_complete = (remaining_len >= total_size);
        } else {
            total_size = headers_len;
            requests[count].is_complete = 1;
        }
        
        // Verifica delimitador [split]
        char *split_delim = strstr(headers_end, "[split]");
        if (split_delim) {
            total_size = split_delim - remaining;
            requests[count].is_complete = 1;
        }
        
        // Aloca e copia os dados da requisição
        requests[count].data = malloc(total_size + 1);
        if (requests[count].data) {
            memcpy(requests[count].data, remaining, total_size);
            requests[count].data[total_size] = '\0';
            requests[count].length = total_size;
            requests[count].offset = offset;
        }
        
        offset += total_size;
        count++;
        
        // Se encontrou [split], pula ele
        if (split_delim) {
            offset += 7;
        }
    }
    
    return count;
}

/* Envia resposta para uma requisição específica */
static void send_response_for_request(int client_sock, HttpRequest *req, const char *status) {
    char resp[4096];
    char ws_key[256] = {0};
    char accept_key[64] = "";
    
    if (req->has_proxyc) {
        /* Modo proxyc:on → duplo 200 */
        snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
        write(client_sock, resp, strlen(resp));
    } else if (req->is_websocket) {
        /* Resposta WebSocket 101 */
        char *key_start = strstr(req->data, "Sec-WebSocket-Key:");
        if (key_start) {
            key_start += 18;
            while (*key_start == ' ' || *key_start == '\t') key_start++;
            char *key_end = strstr(key_start, "\r\n");
            if (!key_end) key_end = strstr(key_start, "\n");
            if (key_end) {
                size_t key_len = key_end - key_start;
                if (key_len < sizeof(ws_key) - 1) {
                    strncpy(ws_key, key_start, key_len);
                    ws_key[key_len] = '\0';
                }
            }
        }
        
        if (ws_key[0]) {
            strcpy(accept_key, generate_websocket_accept(ws_key));
        }
        
        snprintf(resp, sizeof(resp),
            "HTTP/1.1 101 %s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "%s%s\r\n"
            "\r\n",
            status,
            ws_key[0] ? "Sec-WebSocket-Accept: " : "",
            accept_key);
        write(client_sock, resp, strlen(resp));
    } else {
        /* Resposta padrão 200 OK */
        snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
    }
}

/* FUNÇÃO PRINCIPAL REFATORADA */
static void handle_client(int client_sock) {
    char buffer[BUFFER_SIZE] = {0};
    const char *status = get_random_status();
    
    /* Lê todos os dados disponíveis inicialmente */
    ssize_t total_read = 0;
    ssize_t n;
    
    // Primeiro tenta ler com MSG_DONTWAIT (dados já disponíveis)
    while ((n = recv(client_sock, buffer + total_read, 
                     BUFFER_SIZE - total_read - 1, MSG_DONTWAIT)) > 0) {
        total_read += n;
        if (total_read >= BUFFER_SIZE - 1) break;
    }
    
    // Se não leu nada, faz blocking read
    if (total_read == 0) {
        n = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
        if (n <= 0) {
            close(client_sock);
            return;
        }
        total_read = n;
    }
    
    buffer[total_read] = '\0';
    
    /* Divide em requisições individuais */
    HttpRequest requests[MAX_REQUESTS] = {0};
    int req_count = split_requests(buffer, total_read, requests, MAX_REQUESTS);
    
    if (req_count == 0) {
        close(client_sock);
        return;
    }
    
    /* Processa cada requisição */
    int websocket_index = -1;
    size_t processed_until = 0;
    
    for (int i = 0; i < req_count; i++) {
        /* Envia resposta apropriada */
        send_response_for_request(client_sock, &requests[i], status);
        
        /* Marca se é WebSocket */
        if (requests[i].is_websocket) {
            websocket_index = i;
        }
        
        /* Atualiza posição processada */
        if (requests[i].offset + requests[i].length > processed_until) {
            processed_until = requests[i].offset + requests[i].length;
        }
        
        /* Libera memória */
        if (requests[i].data) {
            free(requests[i].data);
        }
    }
    
    /* Se tem WebSocket, mantém conexão para proxy */
    if (websocket_index >= 0) {
        /* Dados extras que podem ser frames WebSocket já no buffer */
        char peek[BUFFER_SIZE] = {0};
        int peeked = 0;
        
        if (processed_until < (size_t)total_read) {
            /* Há dados extras no buffer (provavelmente WebSocket frames) */
            memcpy(peek, buffer + processed_until, total_read - processed_until);
            peeked = total_read - processed_until;
        } else {
            /* Tenta ler novos dados */
            peeked = recv(client_sock, peek, sizeof(peek) - 1, MSG_DONTWAIT);
            if (peeked < 0) peeked = 0;
        }
        
        /* Detecta backend */
        BackendRule *backend = detect_backend(peek, peeked);
        if (!backend) {
            close(client_sock);
            return;
        }
        
        int server_sock = connect_backend(backend->host, backend->port);
        if (server_sock < 0) {
            close(client_sock);
            return;
        }
        
        /* Se temos dados em peek, envia para o backend */
        if (peeked > 0) {
            write(server_sock, peek, peeked);
        }
        
        /* Inicia proxy bidirecional */
        pthread_t t1, t2;
        int *c2s = malloc(2 * sizeof(int));
        int *s2c = malloc(2 * sizeof(int));
        
        if (c2s && s2c) {
            c2s[0] = client_sock;
            c2s[1] = server_sock;
            s2c[0] = server_sock;
            s2c[1] = client_sock;
            
            pthread_create(&t1, NULL, transfer, c2s);
            pthread_create(&t2, NULL, transfer, s2c);
            pthread_join(t1, NULL);
            pthread_join(t2, NULL);
            
            free(c2s);
            free(s2c);
        }
        
        close(server_sock);
    }
    
    close(client_sock);
}

/* ------------------------------------------------------------------ */
/* Base64 encoder simples                                               */
/* ------------------------------------------------------------------ */
static void base64_encode(const unsigned char *data, size_t len, char *out) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j;
    uint32_t val;
    int bits;

    j = 0;
    val = 0;
    bits = -8;
    for (i = 0; i < len; i++) {
        val = (val << 8) | data[i];
        bits += 8;
        while (bits >= 0) {
            out[j++] = table[(val >> bits) & 0x3F];
            bits -= 6;
        }
    }
    if (bits > -8) {
        out[j++] = table[((val << 8) >> (bits + 8)) & 0x3F];
    }
    while (j % 4) out[j++] = '=';
    out[j] = '\0';
}

/* ------------------------------------------------------------------ */
/* Implementação mínima de SHA-1 (RFC 3174)                            */
/* ------------------------------------------------------------------ */
static void SHA1(const unsigned char *input, size_t len, unsigned char output[20]) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE,
             h3 = 0x10325476, h4 = 0xC3D2E1F0;
    uint8_t  msg[64];
    uint32_t w[80];
    size_t   i;

    while (len >= 64) {
        memcpy(msg, input, 64);
        input += 64;
        len   -= 64;
        for (i = 0; i < 16; i++)
            w[i] = ((uint32_t)msg[i*4] << 24) | (msg[i*4+1] << 16) | (msg[i*4+2] << 8) | msg[i*4+3];
        for (i = 16; i < 80; i++)
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
            w[i] = (w[i] << 1) | (w[i] >> 31);

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f, k, temp;
        for (i = 0; i < 80; i++) {
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            temp = (a << 5) | (a >> 27);
            temp += f + e + k + w[i];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }

    memcpy(msg, input, len);
    msg[len++] = 0x80;
    if (len > 56) {
        memset(msg + len, 0, 64 - len);
        len = 0;
        goto process_block;
    process_block:
        for (i = 0; i < 16; i++)
            w[i] = ((uint32_t)msg[i*4] << 24) | (msg[i*4+1] << 16) | (msg[i*4+2] << 8) | msg[i*4+3];
        for (i = 16; i < 80; i++)
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
            w[i] = (w[i] << 1) | (w[i] >> 31);

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f, k, temp;
        for (i = 0; i < 80; i++) {
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            temp = (a << 5) | (a >> 27);
            temp += f + e + k + w[i];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
        if (len == 0) goto final;
    }
    memset(msg + len, 0, 56 - len);
    uint64_t bits = (uint64_t)(len - 1) * 8;
    msg[56] = bits >> 56; msg[57] = bits >> 48;
    msg[58] = bits >> 40; msg[59] = bits >> 32;
    msg[60] = bits >> 24; msg[61] = bits >> 16;
    msg[62] = bits >> 8;  msg[63] = bits;
    goto process_block;

final:
    output[0]  = h0 >> 24; output[1]  = h0 >> 16; output[2]  = h0 >> 8; output[3]  = h0;
    output[4]  = h1 >> 24; output[5]  = h1 >> 16; output[6]  = h1 >> 8; output[7]  = h1;
    output[8]  = h2 >> 24; output[9]  = h2 >> 16; output[10] = h2 >> 8; output[11] = h2;
    output[12] = h3 >> 24; output[13] = h3 >> 16; output[14] = h3 >> 8; output[15] = h3;
    output[16] = h4 >> 24; output[17] = h4 >> 16; output[18] = h4 >> 8; output[19] = h4;
}

/* ------------------------------------------------------------------ */
/* Geração do Sec-WebSocket-Accept                                     */
/* ------------------------------------------------------------------ */
static const char *generate_websocket_accept(const char *key) {
    static char accept[64];
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char combined[512];
    unsigned char sha1[20];

    snprintf(combined, sizeof(combined), "%s%s", key, magic);
    SHA1((unsigned char*)combined, strlen(combined), sha1);
    base64_encode(sha1, 20, accept);
    return accept;
}

/* ------------------------------------------------------------------ */
/* accept_loop (com fork)                                               */
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

    printf("ProxyC rodando na porta %d (IPv4 + IPv6) | "
           "Multi-status: %d | Backends: %d\n",
           PORT, CONFIG.status_count, CONFIG.backend_count);
    printf("Recarregar config: kill -HUP %d\n", getpid());

    accept_loop(server_sock);

    pthread_rwlock_destroy(&config_lock);
    free_config(&CONFIG);
    close(server_sock);
    return 0;
}
