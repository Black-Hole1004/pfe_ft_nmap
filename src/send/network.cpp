#include "functions.hpp"
#include <cstring>

t_tcp_ipv4_packet create_packet(t_technique technique)
{
    t_tcp_ipv4_packet packet;
    std::memset(&packet, 0, sizeof(t_tcp_ipv4_packet));

    packet.ipv4.version  = 4;
    packet.ipv4.ihl      = 5;
    packet.ipv4.tos      = 0;
    packet.ipv4.tot_len  = htons(sizeof(t_packet_header));
    packet.ipv4.id       = htons(12345);
    packet.ipv4.frag_off = 0;
    packet.ipv4.ttl      = 64;
    packet.ipv4.protocol = IPPROTO_TCP;
    packet.ipv4.check    = 0;

    packet.tcp.seq     = htonl(11223344);
    packet.tcp.ack_seq = 0;
    packet.tcp.doff    = 5;
    packet.tcp.window  = htons(1024);
    packet.tcp.check   = 0;
    packet.tcp.urg_ptr = 0;

    if (technique == SYN) {
        packet.tcp.syn = 1;
    }else if (technique == XMAS) {
        packet.tcp.fin = 1;
        packet.tcp.urg = 1;
        packet.tcp.psh = 1;
    }

    return packet;
}

int create_socket(int protocol)
{
    int fd = socket(AF_INET, SOCK_RAW, protocol);
    return fd;
}
