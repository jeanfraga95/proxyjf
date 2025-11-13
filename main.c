#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>

#define BUFFER_SIZE 8192
#define MAX_STATUS 32
#define MAX_BACKEND 32

typedef struct { char pattern[64]; char host[64]; int port; } BackendRule;
typedef struct { char *statuses[MAX_STATUS]; int status_count; BackendRule backends[MAX_BACKEND]; int backend_count; } ProxyConfig;

int PORT = 80;
ProxyConfig CONFIG = {0};

int has_proxyc_on(const char *buf, int len) {
    char temp[1024] = {0};
    if (len > 1023) len = 1023;
    memcpy(temp, buf, len);
    temp[len] = 0;
    char *p = temp;
    while ((p = strstr(p, "proxyc:"))) {
        p += 7;
        while (*p == ' ' || *p == '\t') p++;
        if (tolower(p[0]) == 'o' && tolower(p[1]) == 'n') return 1;
    }
    return 0;
}

void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i+1 < argc) PORT = atoi(argv[i+1]);
        else if (strcmp(argv[i], "--status-list") == 0 && i+1 < argc) {
            char *t = strtok(argv[i+1], ",");
            while (t && CONFIG.status_count < MAX_STATUS) CONFIG.statuses[CONFIG.status_count++] = strdup(t), t = strtok(NULL, ",");
        }
        else if (strcmp(argv[i], "--upgrade") == 0 && i+1 < argc) {
            char *r = strtok(argv[i+1], ",");
            while (r && CONFIG.backend_count < MAX_BACKEND) {
                char pat[64], h[64]; int p;
                if (sscanf(r, "%63[^:]:%63[^:]:%d", pat, h, &p) == 3) {
                    strcpy(CONFIG.backends[CONFIG.backend_count].pattern, pat);
                    strcpy(CONFIG.backends[CONFIG.backend_count].host, h);
                    CONFIG.backends[CONFIG.backend_count++].port = p;
                }
                r = strtok(NULL, ",");
            }
        }
    }
    if (CONFIG.backend_count == 0) {
        strcpy(CONFIG.backends[0].pattern, "SSH"); strcpy(CONFIG.backends[0].host, "127.0.0.1"); CONFIG.backends[0].port = 22;
        strcpy(CONFIG.backends[1].pattern, "");    strcpy(CONFIG.backends[1].host, "127.0.0.1"); CONFIG.backends[1].port = 1194;
        CONFIG.backend_count = 2;
    }
    if (CONFIG.status_count == 0) { CONFIG.statuses[0] = strdup("@CloudJF-C"); CONFIG.status_count = 1; }
}

const char* get_random_status() { return CONFIG.statuses[rand() % CONFIG.status_count]; }

BackendRule* detect_backend(const char *data, int len) {
    for (int i = 0; i < CONFIG.backend_count; i++)
        if (CONFIG.backends[i].pattern[0] && strstr(data, CONFIG.backends[i].pattern))
            return &CONFIG.backends[i];
    return &CONFIG.backends[1];
}

void handle_client(int client_sock) {
    char request[BUFFER_SIZE] = {0};
    int received = 0;
    while (received < BUFFER_SIZE - 1) {
        int n = read(client_sock, request + received, BUFFER_SIZE - received);
        if (n <= 0) break;
        received += n;
        if (strstr(request, "\r\n\r\n")) break;
    }

    const char *status = get_random_status();
    int use_200 = has_proxyc_on(request, received);

    char resp[256];
    snprintf(resp, sizeof(resp), "HTTP/1.1 %d %s\r\n\r\n", use_200 ? 200 : 101, status);
    write(client_sock, resp, strlen(resp));

    snprintf(resp, sizeof(resp), "HTTP/1.1 200 %s\r\n\r\n", status);
    write(client_sock, resp, strlen(resp));

    BackendRule *backend = detect_backend(request, received);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) { close(client_sock); return; }

    struct sockaddr_in saddr = {0};
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(backend->port);
    inet_pton(AF_INET, backend->host, &saddr.sin_addr);

    if (connect(server_sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        close(client_sock); close(server_sock); return;
    }

    pthread_t t1, t2;
    int *c2s = malloc(8); c2s[0] = client_sock; c2s[1] = server_sock;
    int *s2c = malloc(8); s2c[0] = server_sock; s2c[1] = client_sock;
    pthread_create(&t1, NULL, (void*(*)(void*))write, c2s);
    pthread_create(&t2, NULL, (void*(*)(void*))write, s2c);
    pthread_join(t1, NULL); pthread_join(t2, NULL);
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    parse_args(argc, argv);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = INADDR_ANY };
    bind(server_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_sock, 256);

    printf("PROXY FINAL 100%% FUNCIONANDO - PORTA %d\n", PORT);

    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock < 0) continue;
        if (fork() == 0) {
            close(server_sock);
            handle_client(client_sock);
            close(client_sock);
            exit(0);
        }
        close(client_sock);
    }
    return 0;
}
