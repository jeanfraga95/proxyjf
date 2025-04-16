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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <libevent.h>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192

int server_fd = -1;
bool running = true;
const std::string pid_file_path = "/var/run/proxyws.pid";
const std::string log_file_path = "/var/log/proxyws.log";

std::mutex log_mutex;

SSL_CTX *ssl_ctx;

void log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream log_file(log_file_path, std::ios::app);
    log_file << msg << std::endl;
}

int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void cleanup_ssl() {
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
}

void handle_connection(int client_socket, bool is_tls) {
    char buffer[BUFFER_SIZE];
    SSL *ssl = nullptr;

    if (is_tls) {
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0) {
            log("❌ Erro na negociação SSL.");
            SSL_free(ssl);
            close(client_socket);
            return;
        }
    }

    ssize_t bytes = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes <= 0) {
        close(client_socket);
        return;
    }

    std::string response = "HTTP/1.1 101 Proxy Cloud JF\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n\r\n";
    if (send(client_socket, response.c_str(), response.size(), 0) <= 0) {
        log("❌ Erro ao enviar resposta.");
        close(client_socket);
        return;
    }

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

    std::thread([client_socket, ssh_socket, ssl]() {
        char buffer[BUFFER_SIZE];
        ssize_t bytes;
        while ((bytes = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
            if (is_tls) {
                if (SSL_write(ssl, buffer, bytes) <= 0) break;
            } else {
                if (send(ssh_socket, buffer, bytes, 0) <= 0) break;
            }
        }
        shutdown(ssh_socket, SHUT_RDWR);
        close(ssh_socket);
        close(client_socket);
    }).detach();

    std::thread([ssh_socket, client_socket, ssl]() {
        char buffer[BUFFER_SIZE];
        ssize_t bytes;
        while ((bytes = recv(ssh_socket, buffer, sizeof(buffer), 0)) > 0) {
            if (is_tls) {
                if (SSL_write(ssl, buffer, bytes) <= 0) break;
            } else {
                if (send(client_socket, buffer, bytes, 0) <= 0) break;
            }
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
                    // O proxy deve escolher entre usar TLS (WSS) ou não (HTTP, SOCKS5)
                    bool is_tls = false;  // Adicione aqui a lógica para identificar se é TLS (WSS)
                    std::thread(handle_connection, client_socket, is_tls).detach();
                }
            }
        }
    }

    close(epoll_fd);
    close(server_fd);
    remove(pid_file_path.c_str());
    log("🔴 Proxy encerrado.");
}

void setup_ssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        log("❌ Erro ao configurar SSL.");
        exit(1);
    }
    if (!SSL_CTX_use_certificate_file(ssl_ctx, "cert.pem", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ssl_ctx, "key.pem", SSL_FILETYPE_PEM)) {
        log("❌ Erro ao carregar certificado SSL.");
        exit(1);
    }
}

void exibirMenu() {
    while (true) {
        system("clear");
        std::cout << "============================\n";
        std::cout << "      Proxy Cloud JF\n";
        std::cout << "============================\n";
        std::cout << "== 1 - Abrir nova porta   ==\n";
        std::cout << "== 2 - Fechar porta (encerrar proxy da porta)\n";
        std::cout << "== 3 - Matar qualquer processo que use uma porta\n";
        std::cout << "== 4 - Sair do menu (proxy continuará rodando)\n";
        std::cout << "============================\n";
        std::cout << "Escolha uma opção: ";

        int opcao;
        std::cin >> opcao;

        if (opcao == 1) {
            system("clear");
            int porta;
            std::cout << "Digite a porta para abrir: ";
            std::cin >> porta;
            std::thread(run_proxy, porta).detach();
            std::cout << "✅ Proxy iniciado na porta " << porta << ". Pressione Enter...";
            std::cin.ignore(); std::cin.get();
        } else if (opcao == 2) {
            system("clear");
            int porta;
            std::cout << "Digite a porta a ser encerrada: ";
            std::cin >> porta;

            std::string confirm;
            std::cout << "Tem certeza que deseja encerrar a porta " << porta << "? (s/n): ";
            std::cin >> confirm;

            if (confirm == "s" || confirm == "S") {
                std::string comando = "fuser -k " + std::to_string(porta) + "/tcp";
                system(comando.c_str());
                std::cout << "✅ Porta " << porta << " encerrada. Pressione Enter...";
            } else {
                std::cout << "❌ Cancelado. Pressione Enter...";
            }
            std::cin.ignore(); std::cin.get();
        } else if (opcao == 3) {
            system("clear");
            int porta;
            std::cout << "Digite a porta para matar os processos: ";
            std::cin >> porta;

            std::string confirm;
            std::cout << "Tem certeza que deseja MATAR todos os processos da porta " << porta << "? (s/n): ";
            std::cin >> confirm;

            if (confirm == "s" || confirm == "S") {
                std::string comando = "lsof -ti tcp:" + std::to_string(porta) + " | xargs -r kill -9";
                system(comando.c_str());
                std::cout << "☠️  Processos da porta " << porta << " mortos. Pressione Enter...";
            } else {
                std::cout << "❌ Cancelado. Pressione Enter...";
            }
            std::cin.ignore(); std::cin.get();
        } else if (opcao == 4) {
            system("clear");
            std::cout << "👋 Saindo do menu. Proxy continuará em segundo plano.\n";
            break;
        } else {
            std::cout << "❌ Opção inválida. Pressione Enter...";
            std::cin.ignore(); std::cin.get();
        }
    }
}

int main() {
    setup_ssl();
    exibirMenu(); // Chama o menu principal
    cleanup_ssl();
    return 0;
}
