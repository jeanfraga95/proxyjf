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

#define BUFFER_SIZE 32768
#define PEEK_TIMEOUT 1
#define MAX_STATUS 32
#define MAX_BACKEND 32

typedef struct {
    char pattern[64];
    char host[64];
    int port;
} BackendRule;

typedef struct {
    char *statuses[MAX_STATUS];
    int status_count;
    BackendRule backends[MAX_BACKEND];
    int backend_count;
} ProxyConfig;

char *DEFAULT_STATUS = "@jfcloud95";
int PORT = 80;
ProxyConfig CONFIG = {0};

void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            PORT = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "--status") == 0 && i + 1 < argc) {
            DEFAULT_STATUS = argv[i + 1];
        } else if (strcmp(argv[i], "--status-list") == 0 && i + 1 < argc) {
            char *token = strtok(argv[i + 1], ",");
            while (token && CONFIG.status_count < MAX_STATUS) {
                CONFIG.statuses[CONFIG.status_count++] = strdup(token);
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "--upgrade") == 0 && i + 1 < argc) {
            char *rule = strtok(argv[i + 1], ",");
            while (rule && CONFIG.backend_count < MAX_BACKEND) {
                char pattern[64], host[64];
                int port;
                if (sscanf(rule, "%63[^:]:%63[^:]:%d", pattern, host, &port) == 3) {
                    strcpy(CONFIG.backends[CONFIG.backend_count].pattern, pattern);
                    strcpy(CONFIG.backends[CONFIG.backend_count].host, host);
                    CONFIG.backends[CONFIG.backend_count++].port = port;
                }
                rule = strtok(NULL, ",");
            }
        }
    }

    if (CONFIG.backend_count == 0) {
        strcpy(CONFIG.backends[0].pattern, "SSH"); strcpy(CONFIG.backends[0].host, "0.0.0.0"); CONFIG.backends[0].port = 22;
        strcpy(CONFIG.backends[1].pattern, "");    strcpy(CONFIG.backends[1].host, "0.0.0.0"); CONFIG.backends[1].port = 22;
        CONFIG.backend_count = 2;
    }
    if (CONFIG.status_count == 0) {
        CONFIG.statuses[0] = DEFAULT_STATUS;
        CONFIG.status_count = 1;
    }
}

int peek_data(int sock, char *buffer, int len) {
    struct timeval tv = {PEEK_TIMEOUT, 0};
    fd_set fds;
    FD_ZERO(&fds); FD_SET(sock, &fds);
    if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;
    return recv(sock, buffer, len, MSG_PEEK);
}

void *transfer(void *arg) {
    int *fds = (int*)arg;
    char buf[BUFFER_SIZE];
    int bytes;
    while ((bytes = read(fds[0], buf, BUFFER_SIZE)) > 0)
        write(fds[1], buf, bytes);
    shutdown(fds[1], SHUT_WR);
    shutdown(fds[0], SHUT_RD);
    close(fds[0]); close(fds[1]);
    free(fds);
    return NULL;
}

const char* get_random_status() {
    return CONFIG.statuses[rand() % CONFIG.status_count];
}

BackendRule* detect_backend(const char *data, int len) {
    if (len <= 0) return &CONFIG.backends[1];
    for (int i = 0; i < CONFIG.backend_count; i++) {
        if (CONFIG.backends[i].pattern[0] && strstr(data, CONFIG.backends[i].pattern))
            return &CONFIG.backends[i];
    }
    return &CONFIG.backends[1];
}

void handle_client(int client_sock) {
    char buf[BUFFER_SIZE] = {0};
    char resp[256];
    const char *status = get_random_status();

    // Peek the initial request to check for the header
    int peeked = peek_data(client_sock, buf, sizeof(buf)-1);
    int has_proxyc_header = (strstr(buf, "proxyc:on") != NULL) || (strstr(buf, "proxyc: on") != NULL);

    if (has_proxyc_header) {
        // Send 200 twice
        snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
        write(client_sock, resp, strlen(resp));
    } else {
        // Send 101 and then 200
        snprintf(resp, sizeof(resp), "HTTP/1.1 101 %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));

        int received = recv(client_sock, buf, BUFFER_SIZE, 0); // sem bloquear indevidamente
if (received <= 0) {
    close(client_sock);
    return;
}

        snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
    }

    // Now peek for backend detection (after consuming the request if not already)
    if (!has_proxyc_header) {
        snprintf(resp, sizeof(resp), "HTTP/1.1 101 %s\r\n\r\n", status);
        write(client_sock, resp, strlen(resp));
        // Already consumed with read above
    } else {
        // Need to consume the request now
        int received = recv(client_sock, buf, BUFFER_SIZE, 0); // sem bloquear indevidamente
if (received <= 0) {
    close(client_sock);
    return;
}
    }

    char peek[BUFFER_SIZE] = {0};
    int peeked_backend = peek_data(client_sock, peek, sizeof(peek)-1);
    BackendRule *backend = detect_backend(peek, peeked_backend);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) { close(client_sock); return; }

    struct sockaddr_in saddr = {0};
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(backend->port);
    inet_pton(AF_INET, backend->host, &saddr.sin_addr);

    if (connect(server_sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        close(client_sock); close(server_sock);
        return;
    }

    pthread_t t1, t2;
    int *c2s = malloc(2*sizeof(int)); c2s[0]=client_sock; c2s[1]=server_sock;
    int *s2c = malloc(2*sizeof(int)); s2c[0]=server_sock; s2c[1]=client_sock;

    pthread_create(&t1, NULL, transfer, c2s);
    pthread_create(&t2, NULL, transfer, s2c);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}

void *accept_loop(void *arg) {
    int server_sock = *(int*)arg;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (1) {
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            close(server_sock);
            handle_client(client_sock);
            exit(0);
        }
        close(client_sock);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    parse_args(argc, argv);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server_sock, 256) < 0) { perror("listen"); return 1; }

    printf("ProxyC rodando na porta %d | Multi-status: %d | Backends: %d\n", PORT, CONFIG.status_count, CONFIG.backend_count);

    pthread_t thread;
    pthread_create(&thread, NULL, accept_loop, &server_sock);
    pthread_join(thread, NULL);

    for (int i = 0; i < CONFIG.status_count; i++) free(CONFIG.statuses[i]);
    close(server_sock);
    return 0;
}
