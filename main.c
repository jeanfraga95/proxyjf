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

#define VERSION "2.0-FINAL"

/* ------------------------------------------------------------------ */
/* Constantes                                                           */
/* ------------------------------------------------------------------ */
#define BUFFER_SIZE      524288

/* ------------------------------------------------------------------ */
/* Globals                                                              */
/* ------------------------------------------------------------------ */
static int PORT = 80;

/* ------------------------------------------------------------------ */
/* Handlers                                                             */
/* ------------------------------------------------------------------ */
static void handle_sighup(int sig) { (void)sig; }
static void handle_sigchld(int sig) { (void)sig; while (waitpid(-1, NULL, WNOHANG) > 0); }

/* ------------------------------------------------------------------ */
/* Transfer Function                                                    */
/* ------------------------------------------------------------------ */
static void *transfer(void *arg) {
    int *fds = (int *)arg;
    char buf[BUFFER_SIZE];
    ssize_t bytes;
    fprintf(stderr, "[transfer] Túnel %d <-> %d INICIADO\n", fds[0], fds[1]);
    while ((bytes = read(fds[0], buf, BUFFER_SIZE)) > 0) {
        if (write(fds[1], buf, bytes) <= 0) break;
    }
    fprintf(stderr, "[transfer] Túnel %d <-> %d FINALIZADO\n", fds[0], fds[1]);
    shutdown(fds[1], SHUT_WR);
    shutdown(fds[0], SHUT_RD);
    free(fds);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Connect Backend                                                      */
/* ------------------------------------------------------------------ */
static int connect_backend() {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(22);
    inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    fprintf(stderr, "[backend] Conectado em 0.0.0.0:22\n");
    return sock;
}

/* ------------------------------------------------------------------ */
/* Handle Client - Versão Final                                         */
/* ------------------------------------------------------------------ */
static void handle_client(int client_sock) {
    char buf[BUFFER_SIZE] = {0};
    char resp[256] = {0};

    // Peek
    recv(client_sock, buf, sizeof(buf)-1, MSG_PEEK);

    int verb_count = 0;
    if (strstr(buf, "GET ") || strstr(buf, "POST ") || strstr(buf, "CONNECT ")) verb_count++;

    fprintf(stderr, "[v%s] verbos=%d\n", VERSION, verb_count);

    if (verb_count > 1) {
        write(client_sock, "HTTP/1.1 101 Switching Protocols\r\n\r\n", 38);
        write(client_sock, "HTTP/1.1 101 Switching Protocols\r\n\r\n", 38);
    } else {
        write(client_sock, "HTTP/1.1 101 Switching Protocols\r\n\r\n", 38);
    }

    // Consome request
    recv(client_sock, buf, sizeof(buf), 0);

    // 200 OK
    write(client_sock, "HTTP/1.1 200 OK\r\n\r\n", 19);

    // Túnel
    int server_sock = connect_backend();
    if (server_sock < 0) {
        close(client_sock);
        return;
    }

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
/* Accept Loop                                                          */
/* ------------------------------------------------------------------ */
static void accept_loop(int server_sock) {
    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock < 0) continue;

        pid_t pid = fork();
        if (pid == 0) {
            close(server_sock);
            handle_client(client_sock);
            exit(0);
        }
        close(client_sock);
    }
}

int main() {
    printf("ProxyC v%s iniciando...\n", VERSION);

    int server_sock = socket(AF_INET6, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(80);
    addr.sin6_addr = in6addr_any;

    bind(server_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_sock, 256);

    printf("ProxyC v%s rodando na porta 80\n", VERSION);

    accept_loop(server_sock);
    return 0;
}
