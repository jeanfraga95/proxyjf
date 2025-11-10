#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>

#define BUFFER_SIZE 8192
#define PEEK_TIMEOUT 1
#define IDLE_TIMEOUT 300  // 5 minutos de inatividade

char *STATUS_MESSAGE = "ProxyC";
int PORT = 80;

// Função para parsear argumentos da linha de comando
void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            PORT = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "--status") == 0 && i + 1 < argc) {
            STATUS_MESSAGE = argv[i + 1];
        }
    }
}

// Configura socket como não bloqueante
void set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) flags = 0;
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

// PEEK com timeout
int peek_data(int sock, char *buffer, int len, int timeout_sec) {
    struct timeval tv = {timeout_sec, 0};
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    int result = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (result <= 0) return 0;
    return recv(sock, buffer, len, MSG_PEEK);
}

// Função de transferência bidirecional (sem fechar client_sock)
void *transfer(void *arg) {
    int *fds = (int *)arg;
    int src = fds[0], dst = fds[1];
    char buffer[BUFFER_SIZE];
    int bytes;

    while ((bytes = read(src, buffer, BUFFER_SIZE)) > 0) {
        int written = 0;
        while (written < bytes) {
            int n = write(dst, buffer + written, bytes - written);
            if (n <= 0) {
                if (n < 0 && errno == EAGAIN) {
                    usleep(1000);
                    continue;
                }
                break;
            }
            written += n;
        }
        if (written < bytes) break;
    }

    // Apenas desativa escrita no destino
    shutdown(dst, SHUT_WR);
    free(fds);
    return NULL;
}

// Lê cabeçalho HTTP completo (até \r\n\r\n)
int read_http_header(int sock, char *buffer, int max_len) {
    int bytes = 0;
    int header_found = 0;

    while (bytes < max_len - 1) {
        int n = read(sock, buffer + bytes, 1);
        if (n <= 0) {
            if (n < 0 && errno == EAGAIN) {
                usleep(1000);
                continue;
            }
            return -1; // erro ou fechado
        }
        if (bytes >= 3 && memcmp(buffer + bytes - 3, "\r\n\r\n", 4) == 0) {
            header_found = 1;
            break;
        }
        bytes++;
    }
    if (!header_found) return -1;
    buffer[bytes] = '\0';
    return bytes;
}

// Manipula múltiplos túneis na mesma conexão
void handle_client(int client_sock) {
    char buffer[BUFFER_SIZE];
    char peek_buffer[BUFFER_SIZE];
    struct timeval tv = {IDLE_TIMEOUT, 0};

    // Timeout de inatividade
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    set_nonblocking(client_sock);

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(peek_buffer, 0, sizeof(peek_buffer));

        // Lê cabeçalho HTTP
        int header_len = read_http_header(client_sock, buffer, BUFFER_SIZE);
        if (header_len <= 0) {
            break; // erro ou timeout
        }

        // Verifica se é CONNECT ou Upgrade
        int is_connect = (strstr(buffer, "CONNECT") != NULL);
        int is_upgrade = (strstr(buffer, "Upgrade") != NULL);

        if (!is_connect && !is_upgrade) {
            const char *bad = "HTTP/1.1 400 Bad Request\r\n\r\n";
            write(client_sock, bad, strlen(bad));
            continue;
        }

        // Responde apropriadamente
        const char *response;
        if (is_connect) {
            response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        } else {
            char resp[256];
            snprintf(resp, sizeof(resp), "HTTP/1.1 101 %s\r\n\r\n", STATUS_MESSAGE);
            response = resp;
        }
        write(client_sock, response, strlen(response));

        // Detecta protocolo com PEEK
        int peeked = peek_data(client_sock, peek_buffer, BUFFER_SIZE - 1, PEEK_TIMEOUT);
        int target_port = 22; // SSH padrão
        if (peeked > 0) {
            peek_buffer[peeked] = '\0';
            if (strstr(peek_buffer, "SSH") == NULL) {
                target_port = 1194; // OpenVPN
            }
        }

        // Conecta ao backend
        int server_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (server_sock < 0) {
            perror("socket backend");
            continue;
        }

        struct sockaddr_in server_addr = {0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(target_port);
        inet_pton(AF_INET, "0.0.0.0", &server_addr.sin_addr);

        if (connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            printf("Erro ao conectar ao backend 0.0.0.0:%d\n", target_port);
            close(server_sock);
            continue;
        }

        set_nonblocking(server_sock);

        // Cria threads de transferência
        pthread_t t1, t2;
        int *c2s = malloc(2 * sizeof(int));
        int *s2c = malloc(2 * sizeof(int));
        c2s[0] = client_sock; c2s[1] = server_sock;
        s2c[0] = server_sock; s2c[1] = client_sock;

        pthread_create(&t1, NULL, transfer, c2s);
        pthread_create(&t2, NULL, transfer, s2c);

        // Espera o fim do túnel atual
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);

        close(server_sock);
        // client_sock permanece aberto para próximo upgrade
    }

    close(client_sock);
}

// Loop de aceitação (em thread separada)
void *accept_loop(void *arg) {
    int server_sock = *(int *)arg;
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
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
        } else if (pid > 0) {
            close(client_sock);
        } else {
            perror("fork");
            close(client_sock);
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_sock, 128) < 0) {
        perror("listen");
        return 1;
    }

    printf("Proxy multistatus iniciado na porta %d\n", PORT);
    printf("Suporta múltiplos CONNECT/Upgrade na mesma conexão TCP\n");

    pthread_t thread;
    pthread_create(&thread, NULL, accept_loop, &server_sock);
    pthread_join(thread, NULL);

    close(server_sock);
    return 0;
}
