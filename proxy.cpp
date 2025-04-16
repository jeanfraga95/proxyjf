#include <event2/event.h> #include <event2/bufferevent.h> #include <event2/listener.h> #include <netinet/in.h> #include <signal.h> #include <unistd.h> #include <arpa/inet.h> #include <sys/socket.h> #include <sys/types.h> #include <fcntl.h> #include <cstring> #include <iostream> #include <fstream> #include <thread> #include <mutex> #include <map>

std::map<int, pid_t> port_pid_map; std::mutex map_mutex; bool running = true;

void forward_data(evutil_socket_t src, evutil_socket_t dst) { char buffer[4096]; ssize_t n; while ((n = recv(src, buffer, sizeof(buffer), 0)) > 0) { if (send(dst, buffer, n, 0) <= 0) break; } shutdown(src, SHUT_RDWR); shutdown(dst, SHUT_RDWR); close(src); close(dst); }

void handle_connection(evutil_socket_t client_fd, sockaddr_in client_addr) { // Cria conexão com SSH local int ssh_fd = socket(AF_INET, SOCK_STREAM, 0); sockaddr_in ssh_addr{}; ssh_addr.sin_family = AF_INET; ssh_addr.sin_port = htons(22); inet_pton(AF_INET, "127.0.0.1", &ssh_addr.sin_addr);

if (connect(ssh_fd, (sockaddr*)&ssh_addr, sizeof(ssh_addr)) < 0) {
    close(client_fd);
    return;
}

std::thread(forward_data, client_fd, ssh_fd).detach();
std::thread(forward_data, ssh_fd, client_fd).detach();

}

void accept_cb(evconnlistener* listener, evutil_socket_t fd, sockaddr* addr, int, void*) { sockaddr_in* client_addr = (sockaddr_in*)addr; std::thread(handle_connection, fd, *client_addr).detach(); }

void start_proxy(int port) { pid_t pid = fork(); if (pid < 0) return; if (pid > 0) { std::lock_guardstd::mutex lock(map_mutex); port_pid_map[port] = pid; std::ofstream f("/tmp/proxy_" + std::to_string(port) + ".pid"); f << pid; f.close(); return; }

setsid();
signal(SIGCHLD, SIG_IGN);
signal(SIGHUP, SIG_IGN);

struct event_base* base = event_base_new();
sockaddr_in sin{};
sin.sin_family = AF_INET;
sin.sin_addr.s_addr = INADDR_ANY;
sin.sin_port = htons(port);

evconnlistener* listener = evconnlistener_new_bind(base, accept_cb, nullptr,
    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
    (sockaddr*)&sin, sizeof(sin));

if (!listener) {
    perror("evconnlistener");
    exit(1);
}

std::cout << "[PID " << getpid() << "] Proxy escutando na porta " << port << std::endl;
event_base_dispatch(base);

evconnlistener_free(listener);
event_base_free(base);

}

void stop_proxy(int port) { std::ifstream f("/tmp/proxy_" + std::to_string(port) + ".pid"); if (!f.is_open()) { std::cout << "Nenhum proxy em execucao nessa porta.\n"; return; } pid_t pid; f >> pid; kill(pid, SIGTERM); f.close(); remove( ("/tmp/proxy_" + std::to_string(port) + ".pid").c_str() ); std::lock_guardstd::mutex lock(map_mutex); port_pid_map.erase(port); std::cout << "Proxy da porta " << port << " finalizado.\n"; }

void check_port(int port) { std::string cmd = "lsof -i :" + std::to_string(port) + " | grep LISTEN"; system(cmd.c_str()); }

void menu() { std::string op; while (running) { std::cout << "\n==== MENU PROXY ====" << std::endl; std::cout << "1. Abrir porta" << std::endl; std::cout << "2. Fechar porta" << std::endl; std::cout << "3. Ver quem usa porta" << std::endl; std::cout << "4. Sair do menu (proxy continua)" << std::endl; std::cout << "Escolha: "; std::cin >> op;

if (op == "1") {
        int porta;
        std::cout << "Digite a porta: ";
        std::cin >> porta;
        start_proxy(porta);
    } else if (op == "2") {
        int porta;
        std::cout << "Digite a porta a fechar: ";
        std::cin >> porta;
        stop_proxy(porta);
    } else if (op == "3") {
        int porta;
        std::cout << "Porta: ";
        std::cin >> porta;
        check_port(porta);
    } else if (op == "4") {
        std::cout << "Saindo do menu. Proxys continuam...\n";
        break;
    } else {
        std::cout << "Opcao invalida.\n";
    }
}

}

int main() { menu(); return 0; }

