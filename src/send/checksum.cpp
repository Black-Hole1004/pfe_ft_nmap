<<<<<<< HEAD
#include "functions.hpp"
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>


unsigned short checksum(unsigned short *addr, size_t len)
{
    unsigned long sum = 0;
    while(len > 1) {
        sum += *addr++;
        len -= 2;
    }

    if(len == 1) {
        sum += *(unsigned char *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // returns bitwise NOT (~) of sum...
    return (unsigned short)(~sum);
}

void calculate_checksum(u_int8_t protocol, t_tcp_ipv4_packet *packet, unsigned short packet_size, t_IP *IP)
{
    (void)protocol;
    (void)packet_size;
    (void)IP;
    char *raw_ptr = (char *)packet;
    struct iphdr  *ipv4_ptr = (struct iphdr *)(raw_ptr);
    struct tcphdr *tcp_ptr  = (struct tcphdr *)(raw_ptr + sizeof(struct iphdr));

    struct pseudo_header
    {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
    } psh;

    psh.source_address = ipv4_ptr->saddr;
    psh.dest_address   = ipv4_ptr->daddr;
    psh.placeholder    = 0;
    psh.protocol       = IPPROTO_TCP;
    psh.tcp_length     = htons(sizeof(struct tcphdr));

    int pseudo_packet_size = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudo_packet = new char[pseudo_packet_size];

    std::memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    std::memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp_ptr, sizeof(struct tcphdr));

    tcp_ptr->check = checksum((unsigned short *)pseudo_packet, pseudo_packet_size);
    delete[] pseudo_packet;

    ipv4_ptr->check = 0;
    ipv4_ptr->check = checksum((unsigned short *)ipv4_ptr, sizeof(struct iphdr));
}
=======
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
>>>>>>> b39337a23c080e112aeba490d67b505bb7b6703f
