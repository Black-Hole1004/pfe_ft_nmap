#include "functions.hpp"
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>
#include <iostream>

unsigned short checksum(unsigned short *addr, size_t len)
{
    unsigned long sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

void calculate_checksum(u_int8_t protocol, t_packet_header *packet, unsigned short packet_size, t_IP *IP)
{
    unsigned char ip_size = g_scan.options.family == AF_INET ? sizeof(t_ipv4_pseudo_header) : sizeof(t_ipv6_pseudo_header);
    char buffer[ip_size + packet_size];

    if (g_scan.options.family == AF_INET)
    {
        t_ipv4_pseudo_header pseudo_header = {
            .source_address = g_scan.interface.ipv4.sin_addr.s_addr,
            .destination_address = IP->addr.ipv4.sin_addr.s_addr,
            .protocol = protocol,
            .length = htons(packet_size)
        };
        std::memcpy(buffer, &pseudo_header, ip_size);
    }
    else
    {
        t_ipv6_pseudo_header pseudo_header = {
            .length = htonl(packet_size),
            .next_header = protocol
        };
        std::memcpy(pseudo_header.source_address, &g_scan.interface.ipv6.sin6_addr, sizeof(pseudo_header.source_address));
        std::memcpy(pseudo_header.destination_address, &IP->addr.ipv6.sin6_addr, sizeof(pseudo_header.destination_address));
        std::memcpy(buffer, &pseudo_header, ip_size);
    }

    std::memcpy(buffer + ip_size, packet, packet_size);

    if (protocol == IPPROTO_TCP)
        packet->tcp.check = checksum((unsigned short *)buffer, ip_size + packet_size);
    else if (protocol == IPPROTO_UDP)
        packet->udp.check = checksum((unsigned short *)buffer, ip_size + packet_size);
}
