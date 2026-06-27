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

#define VERSION "2.9-FINAL-FIX"
#define BUFFER_SIZE 1048576

static void *transfer(void *arg) {
    int from = ((int*)arg)[0];
    int to   = ((int*)arg)[1];
    free(arg);

    char buf[BUFFER_SIZE];
    ssize_t n;
    fprintf(stderr, "[transfer] Túnel %d <-> %d INICIADO\n", from, to);

    while (1) {
        n = read(from, buf, BUFFER_SIZE);
        if (n <= 0) break;
        if (write(to, buf, n) <= 0) break;
    }

    fprintf(stderr, "[transfer] Túnel %d <-> %d FINALIZADO\n", from, to);
    shutdown(from, SHUT_RDWR);
    shutdown(to, SHUT_RDWR);
    return NULL;
}

static int connect_backend() {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(22);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct timeval tv = {15, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    fprintf(stderr, "[backend] Conectado em 127.0.0.1:22\n");
    return sock;
}

static void handle_client(int client) {
    char buf[BUFFER_SIZE];

    fprintf(stderr, "[v%s] Novo cliente\n", VERSION);

    // Handshake
    write(client, "HTTP/1.1 101 Switching Protocols\r\n\r\n", 38);

    // Drain leve
    for (int i = 0; i < 5; i++) {
        if (recv(client, buf, sizeof(buf), 0) <= 0) break;
    }

    write(client, "HTTP/1.1 200 OK\r\n\r\n", 19);

    int backend = connect_backend();
    if (backend < 0) {
        close(client);
        return;
    }

    // Threads sem join (fire and forget)
    pthread_t t1, t2;
    int *c2s = malloc(2 * sizeof(int)); c2s[0] = client; c2s[1] = backend;
    int *s2c = malloc(2 * sizeof(int)); s2c[0] = backend; s2c[1] = client;

    pthread_create(&t1, NULL, transfer, c2s);
    pthread_create(&t2, NULL, transfer, s2c);

    pthread_detach(t1);
    pthread_detach(t2);

    // Não fecha sockets aqui (threads cuidam)
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