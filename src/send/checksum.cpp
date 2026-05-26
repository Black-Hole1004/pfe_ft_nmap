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

void calculate_checksum(u_int8_t protocol, t_packet_header *packet, unsigned short packet_size, t_IP *IP)
{
    (void)protocol;
    (void)packet_size;
    (void)IP;

    struct pseudo_header
    {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
    } psh;

    psh.source_address = packet->ipv4.saddr;
    psh.dest_address   = packet->ipv4.daddr;
    psh.placeholder    = 0;
    psh.protocol       = IPPROTO_TCP;
    psh.tcp_length     = htons(sizeof(struct tcphdr));

    int pseudo_packet_size = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudo_packet = new char[pseudo_packet_size];

    std::memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    std::memcpy(pseudo_packet + sizeof(struct pseudo_header), &(packet->tcp), sizeof(struct tcphdr));

    packet->tcp.check = checksum((unsigned short *)pseudo_packet, pseudo_packet_size);

    delete[] pseudo_packet;
}
