#include "functions.hpp"
#include <cstring>
#include <errno.h>
#include <iostream>
#include <unistd.h>

t_packet_header create_packet(t_technique technique)
{
    t_packet_header packet;
    std::memset(&packet, 0, sizeof(t_packet_header));

    if (technique == UDP)
    {
        packet.udp.source = htons(technique);
        packet.udp.len = htons(sizeof(struct udphdr));
        return packet;
    }

    // TCP header only — kernel builds IP header when IP_HDRINCL is off
    packet.tcp.source = htons(technique);
    packet.tcp.doff = 5; // 20 bytes
    packet.tcp.window = htons(1024);

    packet.tcp.ack = technique == ACK;
    packet.tcp.syn = technique == SYN;
    packet.tcp.fin = technique == FIN || technique == XMAS;
    packet.tcp.psh = technique == XMAS;
    packet.tcp.urg = technique == XMAS;

    return packet;
}

int create_socket(int protocol)
{
    int sock = socket(g_scan.options.family, SOCK_RAW, protocol);
    if (sock == -1) {
        std::cerr << "socket: " << strerror(errno) << std::endl;
        return -1;
    }

    int optval = 1024 * 1024;
    // SO_SNDBUF works without elevated capabilities; SO_SNDBUFFORCE needs CAP_NET_ADMIN
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval)) == -1) {
        std::cerr << "setsockopt: " << strerror(errno) << std::endl;
        // Non-fatal: continue with default buffer size
    }

    if (g_scan.options.family == AF_INET)
        bind(sock, (struct sockaddr *)&g_scan.interface.ipv4, sizeof(g_scan.interface.ipv4));
    else
        bind(sock, (struct sockaddr *)&g_scan.interface.ipv6, sizeof(g_scan.interface.ipv6));

    return sock;
}
