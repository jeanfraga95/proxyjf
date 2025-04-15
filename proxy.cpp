#include <iostream>
#include <fstream>
#include <thread>
#include <unistd.h>
#include <csignal>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>
#include <mutex>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192

int server_fd = -1;
bool running = true;
const std::string pid_file_path = "/var/run/proxyws.pid";
const std::string log_file_path = "/var/log/proxyws.log";

std::mutex log_mutex;

void log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream log_file(log_file_path, std::ios::app);
    log_file << msg << std::endl;
}

int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void handle_connection(int client_socket) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes <= 0) {
        close(client_socket);
        return;
    }

    std::string response = "HTTP/1.1 101 Proxy Cloud JF\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n\r\n";
    send(client_socket, response.c_str(), response.size(), 0);

    int ssh_socket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in ssh_addr{};
    ssh_addr.sin_family = AF_INET;
    ssh_addr.sin_port = htons(22);
    inet_pton(AF_INET, "127.0.0.1", &ssh_addr.sin_addr);

    if (connect(ssh_socket, (struct sockaddr*)&ssh_addr, sizeof(ssh_addr)) < 0) {
        log("❌ Erro ao conectar ao OpenSSH.");
        close(client_socket);
        close(ssh_socket);
        return;
    }

    log("🔗 Cliente conectado e redirecionado para OpenSSH.");

    std::thread([client_socket, ssh_socket]() {
        char buffer[BUFFER_SIZE];
        ssize_t bytes;
        while ((bytes = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
            if (send(ssh_socket, buffer, bytes, 0) <= 0) break;
        }
        shutdown(ssh_socket, SHUT_RDWR);
        close(ssh_socket);
        close(client_socket);
    }).detach();

    std::thread([ssh_socket, client_socket]() {
        char buffer[BUFFER_SIZE];
        ssize_t bytes;
        while ((bytes = recv(ssh_socket, buffer, sizeof(buffer), 0)) > 0) {
            if (send(client_socket, buffer, bytes, 0) <= 0) break;
        }
        shutdown(client_socket, SHUT_RDWR);
        close(client_socket);
        close(ssh_socket);
    }).detach();
}

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        running = false;
        if (server_fd != -1) close(server_fd);
    }
}

void run_proxy(int port) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log("❌ Erro ao criar socket do servidor.");
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log("❌ Erro ao vincular porta.");
        return;
    }

    if (listen(server_fd, SOMAXCONN) < 0) {
        log("❌ Erro ao escutar conexões.");
        return;
    }

    set_non_blocking(server_fd);

    std::ofstream pid_file(pid_file_path);
    pid_file << getpid();
    pid_file.close();

    log("🟢 Proxy iniciado na porta " + std::to_string(port));

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        log("❌ Falha ao criar epoll.");
        return;
    }

    epoll_event event{}, events[MAX_EVENTS];
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event);

    while (running) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == server_fd) {
                sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_socket = accept(server_fd, (sockaddr*)&client_addr, &client_len);
                if (client_socket >= 0) {
                    set_non_blocking(client_socket);
                    std::thread(handle_connection, client_socket).detach();
                }
            }
        }
    }

    close(epoll_fd);
    close(server_fd);
    remove(pid_file_path.c_str());
    log("🔴 Proxy encerrado.");
}

int main() {
    int porta = 80;
    std::cout << "Digite a porta para o proxy: ";
    std::cin >> porta;
    run_proxy(porta);
    return 0;
}
