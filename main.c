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

#define VERSION "2.7-AGGRESSIVE-GO-MATCH"
#define BUFFER_SIZE 1048576

static void *transfer(void *arg) {
    int *fds = (int*)arg;
    char buf[BUFFER_SIZE];
    ssize_t n;
    fprintf(stderr, "[transfer] Túnel %d <-> %d INICIADO\n", fds[0], fds[1]);
    while ((n = read(fds[0], buf, BUFFER_SIZE)) > 0) {
        if (write(fds[1], buf, n) <= 0) break;
    }
    fprintf(stderr, "[transfer] Túnel %d <-> %d FINALIZADO\n", fds[0], fds[1]);
    shutdown(fds[0], SHUT_RDWR);
    shutdown(fds[1], SHUT_RDWR);
    free(fds);
    return NULL;
}

static int connect_backend() {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(22);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    fprintf(stderr, "[backend] Conectado em 127.0.0.1:22\n");
    return sock;
}

static void handle_client(int client) {
    char buf[BUFFER_SIZE];
    ssize_t n;

    // Peek agressivo
    n = recv(client, buf, sizeof(buf)-1, MSG_PEEK);
    if (n > 0) buf[n] = '\0';

    fprintf(stderr, "[v%s] verbos=1 (client peek %zd bytes)\n", VERSION, n);

    // Handshake idêntico ao Go (101 + drain + 200)
    write(client, "HTTP/1.1 101 Switching Protocols\r\n\r\n", 38);

    // Drain muito agressivo (como o Go faz)
    for (int i = 0; i < 30; i++) {
        n = recv(client, buf, sizeof(buf), 0);
        if (n <= 0) break;
        fprintf(stderr, "[drain] Consumidos %zd bytes\n", n);
    }

    write(client, "HTTP/1.1 200 OK\r\n\r\n", 19);

    int backend = connect_backend();
    if (backend < 0) {
        close(client);
        return;
    }

    pthread_t t1, t2;
    int *c2s = malloc(2 * sizeof(int)); c2s[0] = client; c2s[1] = backend;
    int *s2c = malloc(2 * sizeof(int)); s2c[0] = backend; s2c[1] = client;

    pthread_create(&t1, NULL, transfer, c2s);
    pthread_create(&t2, NULL, transfer, s2c);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(client);
    close(backend);
}

int main() {
    printf("ProxyC v%s iniciando...\n", VERSION);

    int s = socket(AF_INET6, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(80);
    addr.sin6_addr = in6addr_any;

    bind(s, (struct sockaddr*)&addr, sizeof(addr));
    listen(s, 1024);

    printf("ProxyC v%s rodando na porta 80\n", VERSION);

    while (1) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        if (fork() == 0) {
            close(s);
            handle_client(c);
            exit(0);
        }
        close(c);
    }
}