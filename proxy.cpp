#include <iostream>
#include <fstream>
#include <thread>
#include <unistd.h>
#include <csignal>
#include <cstring>
#include <mutex>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <cstdlib>

bool running = false;
int server_fd = -1;
int port_global = 80;
std::thread server_thread;
std::mutex cout_mutex;

const std::string pid_file_path = "/var/run/proxyws.pid";
const std::string log_file_path = "/var/log/proxyws.log";

void log(const std::string& msg) {
    std::ofstream log_file(log_file_path, std::ios::app);
    log_file << msg << std::endl;
}

void forward_data(int src, int dst) {
    char buffer[8192];
    ssize_t bytes;
    while ((bytes = recv(src, buffer, sizeof(buffer), 0)) > 0) {
        if (send(dst, buffer, bytes, 0) < 0) break;
    }
    shutdown(dst, SHUT_RDWR);
    shutdown(src, SHUT_RDWR);
    close(dst);
    close(src);
}

void handle_client(int client_socket) {
    char buffer[4096];
    ssize_t bytes = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes <= 0) {
        close(client_socket);
        return;
    }

    std::string response = "Proxy Cloud JF\r\n"
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
    std::thread(forward_data, client_socket, ssh_socket).detach();
    std::thread(forward_data, ssh_socket, client_socket).detach();
}

bool is_port_in_use(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bool in_use = bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0;
    close(sock);
    return in_use;
}

bool is_port_still_open(int port) {
    std::string cmd = "lsof -i :" + std::to_string(port) + " > /dev/null 2>&1";
    return system(cmd.c_str()) == 0;
}

void force_kill_port(int port) {
    std::string cmd = "lsof -t -i :" + std::to_string(port);
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return;

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        int pid = std::stoi(buffer);
        kill(pid, SIGKILL);
        std::cout << "⚠️ Processo " << pid << " na porta " << port << " foi encerrado à força.\n";
        log("⚠️ Processo " + std::to_string(pid) + " na porta " + std::to_string(port) + " foi encerrado à força.");
    }

    pclose(pipe);
}

void handle_signal(int signal) {
    if (signal == SIGTERM || signal == SIGINT) {
        running = false;
        if (server_fd != -1) {
            close(server_fd);
        }
    }
}

void run_proxy(int port) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    sockaddr_in address{};
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log("❌ Falha ao criar socket.");
        return;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        log("❌ Porta já está em uso.");
        return;
    }

    if (listen(server_fd, 1024) < 0) {
        log("❌ Falha ao escutar conexões.");
        return;
    }

    std::ofstream pid_file(pid_file_path);
    pid_file << getpid();
    pid_file.close();

    log("🟢 Proxy Cloud JF ativo na porta " + std::to_string(port) + ". Aguardando conexões...");
    running = true;

    while (running) {
        int client_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (client_socket >= 0 && running) {
            std::thread(handle_client, client_socket).detach();
        } else {
            close(client_socket);
        }
    }

    close(server_fd);
    remove(pid_file_path.c_str());
    log("🔴 Proxy encerrado.");
}

void start_daemon(int port) {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    setsid();
    umask(0);

    int fd = open(log_file_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);

    run_proxy(port);
}

void menu() {
    std::string opcao;
    while (true) {
        std::cout << "==== MENU DO PROXY Cloud JF ====\n";
        std::cout << "⚠️  O Proxy não funciona com OpenVPN\n";
        std::cout << "1. Abrir proxy\n";
        std::cout << "2. Fechar proxy\n";
        std::cout << "3. Sair\n";
        std::cout << "Escolha: ";
        std::cin >> opcao;

        if (opcao == "1") {
            std::ifstream pid_file(pid_file_path);
            if (pid_file.good()) {
                std::cout << "⚠️ Proxy já está rodando.\n";
            } else {
                std::cout << "Digite a porta: ";
                std::cin >> port_global;
                std::cout << "Proxy Iniciado Agora seja Feliz";

                if (is_port_in_use(port_global)) {
                    std::cout << "❌ Porta já está em uso.\n";
                } else {
                    start_daemon(port_global);
                    std::cout << "✅ Proxy iniciado. Verifique log em /var/log/proxyws.log\n";
                }
            }
        } else if (opcao == "2") {
            std::ifstream pid_file(pid_file_path);
            if (pid_file.good()) {
                int pid;
                pid_file >> pid;
                pid_file.close();
                kill(pid, SIGTERM);
                sleep(1);

                if (is_port_still_open(port_global)) {
                    std::cout << "⚠️ A porta " << port_global << " ainda está ocupada. Encerrando à força...\n";
                    force_kill_port(port_global);
                } else {
                    std::cout << "✅ Porta liberada com sucesso.\n";
                }

                remove(pid_file_path.c_str());
                std::cout << "🔴 Proxy encerrado.\n";
                log("🔴 Proxy encerrado via menu.");
            } else {
                std::cout << "⚠️ Nenhum proxy rodando.\n";
            }
        } else if (opcao == "3") {
            break;
        } else {
            std::cout << "❌ Opção inválida!\n";
        }

        std::cout << "Pressione ENTER para continuar...";
        std::cin.ignore();
        std::cin.get();
    }
}

int main() {
    menu();
    return 0;
}
