#include <iostream>
#include <event2/event.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <csignal>
#include <fcntl.h>
#include <thread>
#include <map>
#include <mutex>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

std::map<int, pid_t> port_pid_map;
std::mutex map_mutex;

void forward_data(int src, int dst) {
    char buffer[4096];
    ssize_t bytes;
    while ((bytes = recv(src, buffer, sizeof(buffer), 0)) > 0) {
        if (send(dst, buffer, bytes, 0) < 0) break;
    }
    shutdown(src, SHUT_RDWR);
    shutdown(dst, SHUT_RDWR);
    close(src);
    close(dst);
}

void handle_connection(int client_fd, sockaddr_in client_addr) {
    int ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in ssh_addr{};
    ssh_addr.sin_family = AF_INET;
    ssh_addr.sin_port = htons(22);
    inet_pton(AF_INET, "127.0.0.1", &ssh_addr.sin_addr);

    if (connect(ssh_fd, (sockaddr*)&ssh_addr, sizeof(ssh_addr)) < 0) {
        close(client_fd);
        return;
    }

    std::thread(forward_data, client_fd, ssh_fd).detach();
    std::thread(forward_data, ssh_fd, client_fd).detach();
}

void on_accept(evutil_socket_t listener, short, void*) {
    sockaddr_in client_addr{};
    socklen_t slen = sizeof(client_addr);
    int client_fd = accept(listener, (sockaddr*)&client_addr, &slen);
    if (client_fd >= 0) {
        handle_connection(client_fd, client_addr);
    }
}

void start_proxy(int port) {
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid > 0) {
        std::lock_guard<std::mutex> lock(map_mutex);
        port_pid_map[port] = pid;
        std::ofstream f("/tmp/proxy_" + std::to_string(port) + ".pid");
        f << pid;
        f.close();
        return;
    }

    umask(0);
    setsid();
    chdir("/");

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    evutil_make_socket_nonblocking(fd);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(fd, (sockaddr*)&addr, sizeof(addr));
    listen(fd, 128);

    event_base* base = event_base_new();
    event* ev = event_new(base, fd, EV_READ | EV_PERSIST, on_accept, nullptr);
    event_add(ev, nullptr);
    event_base_dispatch(base);
    close(fd);
}

void stop_proxy(int port) {
    std::string pid_file = "/tmp/proxy_" + std::to_string(port) + ".pid";
    std::ifstream f(pid_file);
    if (!f.is_open()) {
        std::cout << "❌ Nenhum proxy rodando na porta " << port << "\n";
        return;
    }
    pid_t pid;
    f >> pid;
    kill(pid, SIGTERM);
    remove(pid_file.c_str());
    std::lock_guard<std::mutex> lock(map_mutex);
    port_pid_map.erase(port);
    std::cout << "🔴 Proxy da porta " << port << " finalizado.\n";
}

void show_port_owner(int port) {
    std::string cmd = "lsof -i :" + std::to_string(port) + " | grep LISTEN";
    std::cout << "Serviços escutando na porta " << port << ":\n";
    system(cmd.c_str());
}

void menu() {
    while (true) {
        std::string opt;
        std::cout << "\n=== MENU DO PROXY ===\n";
        std::cout << "1. Abrir porta\n";
        std::cout << "2. Fechar porta\n";
        std::cout << "3. Ver quem está usando a porta\n";
        std::cout << "4. Sair\n";
        std::cout << "Escolha: ";
        std::cin >> opt;

        if (opt == "1") {
            int porta;
            std::cout << "Digite a porta para abrir: ";
            std::cin >> porta;
            start_proxy(porta);
            std::cout << "🟢 Proxy iniciado na porta " << porta << "\n";
        } else if (opt == "2") {
            int porta;
            std::cout << "Digite a porta para fechar: ";
            std::cin >> porta;
            stop_proxy(porta);
        } else if (opt == "3") {
            int porta;
            std::cout << "Digite a porta para verificar: ";
            std::cin >> porta;
            show_port_owner(porta);
        } else if (opt == "4") {
            std::cout << "Saindo do menu...\n";
            break;
        } else {
            std::cout << "Opção inválida.\n";
        }
    }
}

int main() {
    menu();
    return 0;
}