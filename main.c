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
#include <time.h>
#define BUFFER_SIZE 8192
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
char *DEFAULT_STATUS = "@RustyManager";
int PORT = 80;
ProxyConfig CONFIG = {0};
void parse_args(int argc, char *argv[]) {
for (int i = 1; i < argc; i++) {
if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
PORT = atoi(argv[i + 1]);
} else if (strcmp(argv[i], "--status") == 0 && i + 1 < argc) {
DEFAULT_STATUS = argv[i + 1];
} else if (strcmp(argv[i], "--status-list") == 0 && i + 1 < argc) {
char *list = argv[i + 1];
char *token = strtok(list, ",");
while (token && CONFIG.status_count < MAX_STATUS) {
CONFIG.statuses[CONFIG.status_count++] = strdup(token);
token = strtok(NULL, ",");
}
} else if (strcmp(argv[i], "--upgrade") == 0 && i + 1 < argc) {
char *rules = argv[i + 1];
char *rule = strtok(rules, ",");
while (rule && CONFIG.backend_count < MAX_BACKEND) {
char pattern[64], host[64];
int port;
if (sscanf(rule, "%63[^:]:%63[^:]:%d", pattern, host, &port) == 3) {
strcpy(CONFIG.backends[CONFIG.backend_count].pattern, pattern);
strcpy(CONFIG.backends[CONFIG.backend_count].host, host);
CONFIG.backends[CONFIG.backend_count].port = port;
CONFIG.backend_count++;
}
rule = strtok(NULL, ",");
}
}
}
// Fallbacks se não definidos
if (CONFIG.backend_count == 0) {
strcpy(CONFIG.backends[0].pattern, "SSH");
strcpy(CONFIG.backends[0].host, "0.0.0.0");
CONFIG.backends[0].port = 22;
strcpy(CONFIG.backends[1].pattern, "");
strcpy(CONFIG.backends[1].host, "0.0.0.0");
CONFIG.backends[1].port = 1194;
CONFIG.backend_count = 2;
}
if (CONFIG.status_count == 0) {
CONFIG.statuses[0] = DEFAULT_STATUS;
CONFIG.status_count = 1;
}
}
void set_nonblocking(int sock) {
int flags = fcntl(sock, F_GETFL, 0);
fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}
int peek_data(int sock, char *buffer, int len, int timeout_sec) {
struct timeval tv = {timeout_sec, 0};
fd_set readfds;
FD_ZERO(&readfds);
FD_SET(sock, &readfds);
int result = select(sock + 1, &readfds, NULL, NULL, &tv);
if (result <= 0) return 0;
return recv(sock, buffer, len, MSG_PEEK);
}
void *transfer(void *arg) {
int *fds = (int *)arg;
int src = fds[0], dst = fds[1];
char buffer[BUFFER_SIZE];
int bytes;
while ((bytes = read(src, buffer, BUFFER_SIZE)) > 0) {
write(dst, buffer, bytes);
}
shutdown(dst, SHUT_WR);
shutdown(src, SHUT_RD);
free(fds);
return NULL;
}
const char* get_random_status() {
if (CONFIG.status_count == 0) return DEFAULT_STATUS;
int idx = rand() % CONFIG.status_count;
return CONFIG.statuses[idx];
}
BackendRule* detect_backend(const char *data, int len) {
if (len <= 0) return &CONFIG.backends[1]; // Fallback
char peek_str[BUFFER_SIZE] = {0};
int copy_len = len < BUFFER_SIZE - 1 ? len : BUFFER_SIZE - 1;
memcpy(peek_str, data, copy_len);
peek_str[copy_len] = '\0';
for (int i = 0; i < CONFIG.backend_count; i++) {
if (CONFIG.backends[i].pattern[0] == '\0') continue;
if (strstr(peek_str, CONFIG.backends[i].pattern)) {
return &CONFIG.backends[i];
}
}
return &CONFIG.backends[1]; // Fallback
}
void handle_client(int client_sock) {
char buffer[BUFFER_SIZE] = {0};
char response[256];
const char *status = get_random_status();
snprintf(response, sizeof(response), "HTTP/1.1 101 %s\r\n\r\n", status);
write(client_sock, response, strlen(response));
read(client_sock, buffer, BUFFER_SIZE);
snprintf(response, sizeof(response), "HTTP/1.1 200 %s\r\n\r\n", status);
write(client_sock, response, strlen(response));
char peek_buffer[BUFFER_SIZE] = {0};
int peeked = peek_data(client_sock, peek_buffer, BUFFER_SIZE - 1, PEEK_TIMEOUT);
BackendRule *backend = detect_backend(peek_buffer, peeked);
int server_sock = socket(AF_INET, SOCK_STREAM, 0);
if (server_sock < 0) {
close(client_sock);
return;
}
struct sockaddr_in server_addr = {0};
server_addr.sin_family = AF_INET;
server_addr.sin_port = htons(backend->port);
inet_pton(AF_INET, backend->host, &server_addr.sin_addr);
if (connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
printf("Erro ao conectar ao backend %s:%d\n", backend->host, backend->port);
close(client_sock);
close(server_sock);
return;
}
set_nonblocking(client_sock);
set_nonblocking(server_sock);
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
void *accept_loop(void *arg) {
int server_sock = *(int )arg;
while (1) {
struct sockaddr_in client_addr;
socklen_t client_len = sizeof(client_addr);
int client_sock = accept(server_sock, (struct sockaddr)&client_addr, &client_len);
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
}
}
return NULL;
}
int main(int argc, char *argv[]) {
srand(time(NULL));
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
printf("Iniciando serviço na porta: %d\n", PORT);
pthread_t thread;
pthread_create(&thread, NULL, accept_loop, &server_sock);
pthread_join(thread, NULL);
for (int i = 0; i < CONFIG.status_count; i++) {
free(CONFIG.statuses[i]);
}
close(server_sock);
return 0;
}
