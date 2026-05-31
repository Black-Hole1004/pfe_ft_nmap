#include "functions.hpp"

int raw_socket_fd = -1; // raw socket file descriptor

void init_send() {
    raw_socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (raw_socket_fd < 0)
    {
        std::cout << ">>Error: Root privileges required to claim raw sockets." << std::endl;
        return;
    }

    int integer = 1;
    if (setsockopt(raw_socket_fd, IPPROTO_IP, IP_HDRINCL, &integer, sizeof(integer)) < 0)
    {
        std::cout << ">>>Warning: IP_HDRINCL options could not be initialized explicitly." << std::endl;
    }
}