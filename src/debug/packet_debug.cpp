// TEMPORARY DEBUG FILE - TO BE REMOVED AFTER DEBUGGING
// This file contains packet printing functions for debugging purposes

#include "packet_debug.hpp"
#include <iostream>
#include <iomanip>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

void print_hex_dump(const unsigned char *data, size_t len, const std::string& prefix)
{
    std::cout << prefix << "Hex dump (" << len << " bytes):" << std::endl;
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0)
            std::cout << prefix << "  " << std::setfill('0') << std::setw(4) << std::hex << i << ":  ";
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)data[i] << " ";
        if ((i + 1) % 16 == 0 || i == len - 1) {
            // Print ASCII representation
            int padding = (15 - (i % 16)) * 3;
            for (int p = 0; p < padding; p++)
                std::cout << " ";
            std::cout << " | ";
            for (size_t j = i - (i % 16); j <= i; j++) {
                char c = data[j];
                std::cout << (c >= 32 && c <= 126 ? c : '.');
            }
            std::cout << std::endl;
        }
    }
    std::cout << std::dec; // reset to decimal
}

void print_tcp_flags(const struct tcphdr *tcp)
{
    std::cout << "    Flags: ";
    if (tcp->syn) std::cout << "SYN ";
    if (tcp->ack) std::cout << "ACK ";
    if (tcp->fin) std::cout << "FIN ";
    if (tcp->rst) std::cout << "RST ";
    if (tcp->psh) std::cout << "PSH ";
    if (tcp->urg) std::cout << "URG ";
    std::cout << std::endl;
}

void print_outgoing_packet(const t_packet_header *packet, int protocol,
                           const char *dest_ip, int dest_port, const char *technique_name)
{
    std::cout << "\n========== OUTGOING PACKET ==========" << std::endl;
    std::cout << "Technique: " << technique_name << std::endl;
    std::cout << "Destination: " << dest_ip << ":" << dest_port << std::endl;

    if (protocol == IPPROTO_TCP) {
        std::cout << "\n[TCP Header]" << std::endl;
        std::cout << "  Source Port: " << ntohs(packet->tcp.source) << std::endl;
        std::cout << "  Dest Port: " << ntohs(packet->tcp.dest) << std::endl;
        std::cout << "  Sequence: " << ntohl(packet->tcp.seq) << std::endl;
        std::cout << "  Ack Sequence: " << ntohl(packet->tcp.ack_seq) << std::endl;
        std::cout << "  Data Offset: " << (int)packet->tcp.doff << " (header size: " << (packet->tcp.doff * 4) << " bytes)" << std::endl;
        print_tcp_flags(&packet->tcp);
        std::cout << "  Window: " << ntohs(packet->tcp.window) << std::endl;
        std::cout << "  Checksum: 0x" << std::hex << ntohs(packet->tcp.check) << std::dec << std::endl;
        std::cout << "  Urgent Pointer: " << ntohs(packet->tcp.urg_ptr) << std::endl;

        print_hex_dump((const unsigned char *)packet, sizeof(struct tcphdr), "  ");
    }
    else if (protocol == IPPROTO_UDP) {
        std::cout << "\n[UDP Header]" << std::endl;
        std::cout << "  Source Port: " << ntohs(packet->udp.source) << std::endl;
        std::cout << "  Dest Port: " << ntohs(packet->udp.dest) << std::endl;
        std::cout << "  Length: " << ntohs(packet->udp.len) << std::endl;
        std::cout << "  Checksum: 0x" << std::hex << ntohs(packet->udp.check) << std::dec << std::endl;

        print_hex_dump((const unsigned char *)packet, sizeof(struct udphdr), "  ");
    }
    std::cout << "====================================\n" << std::endl;
}

void print_incoming_packet(const unsigned char *data, size_t packet_len, int link_type)
{
    std::cout << "\n========== INCOMING PACKET ==========" << std::endl;
    std::cout << "Total packet length: " << packet_len << " bytes" << std::endl;
    std::cout << "Link type: " << link_type << std::endl;

    // Determine offset based on link type
    int offset = 14; // ethernet
    if (link_type == DLT_LINUX_SLL)
        offset = 16;
    else if (link_type == DLT_NULL)
        offset = 4;

    std::cout << "Link layer offset: " << offset << " bytes" << std::endl;

    const unsigned char *ip_data = data + offset;

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)ip_data;

    std::cout << "\n[IP Header]" << std::endl;
    std::cout << "  Version: " << (int)(ip->version) << std::endl;
    std::cout << "  Header Length: " << (int)(ip->ihl * 4) << " bytes" << std::endl;
    std::cout << "  Total Length: " << ntohs(ip->tot_len) << std::endl;
    std::cout << "  Protocol: " << (int)ip->protocol;
    if (ip->protocol == IPPROTO_TCP)
        std::cout << " (TCP)";
    else if (ip->protocol == IPPROTO_UDP)
        std::cout << " (UDP)";
    else if (ip->protocol == IPPROTO_ICMP)
        std::cout << " (ICMP)";
    std::cout << std::endl;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->daddr, dst_ip, INET_ADDRSTRLEN);
    std::cout << "  Source IP: " << src_ip << std::endl;
    std::cout << "  Dest IP: " << dst_ip << std::endl;

    const unsigned char *transport_data = ip_data + (ip->ihl * 4);

    // Parse transport layer
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)transport_data;
        std::cout << "\n[TCP Header]" << std::endl;
        std::cout << "  Source Port: " << ntohs(tcp->source) << std::endl;
        std::cout << "  Dest Port: " << ntohs(tcp->dest) << std::endl;
        std::cout << "  Sequence: " << ntohl(tcp->seq) << std::endl;
        std::cout << "  Ack Sequence: " << ntohl(tcp->ack_seq) << std::endl;
        std::cout << "  Data Offset: " << (int)tcp->doff << " (header size: " << (tcp->doff * 4) << " bytes)" << std::endl;
        print_tcp_flags(tcp);
        std::cout << "  Window: " << ntohs(tcp->window) << std::endl;
        std::cout << "  Checksum: 0x" << std::hex << ntohs(tcp->check) << std::dec << std::endl;

        print_hex_dump(transport_data, tcp->doff * 4, "  ");
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)transport_data;
        std::cout << "\n[UDP Header]" << std::endl;
        std::cout << "  Source Port: " << ntohs(udp->source) << std::endl;
        std::cout << "  Dest Port: " << ntohs(udp->dest) << std::endl;
        std::cout << "  Length: " << ntohs(udp->len) << std::endl;
        std::cout << "  Checksum: 0x" << std::hex << ntohs(udp->check) << std::dec << std::endl;

        print_hex_dump(transport_data, sizeof(struct udphdr), "  ");
    }
    else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)transport_data;
        std::cout << "\n[ICMP Header]" << std::endl;
        std::cout << "  Type: " << (int)icmp->type;
        if (icmp->type == ICMP_ECHOREPLY) std::cout << " (Echo Reply)";
        else if (icmp->type == ICMP_DEST_UNREACH) std::cout << " (Destination Unreachable)";
        else if (icmp->type == ICMP_TIME_EXCEEDED) std::cout << " (Time Exceeded)";
        std::cout << std::endl;
        std::cout << "  Code: " << (int)icmp->code << std::endl;
        std::cout << "  Checksum: 0x" << std::hex << ntohs(icmp->checksum) << std::dec << std::endl;

        print_hex_dump(transport_data, sizeof(struct icmphdr), "  ");

        // For ICMP unreachable, show the embedded packet
        if (icmp->type == ICMP_DEST_UNREACH) {
            std::cout << "\n  [Embedded Packet]" << std::endl;
            const unsigned char *embedded = transport_data + sizeof(struct icmphdr);
            struct iphdr *embedded_ip = (struct iphdr *)embedded;

            std::cout << "    Original Protocol: " << (int)embedded_ip->protocol;
            if (embedded_ip->protocol == IPPROTO_TCP) std::cout << " (TCP)";
            else if (embedded_ip->protocol == IPPROTO_UDP) std::cout << " (UDP)";
            std::cout << std::endl;

            const unsigned char *embedded_transport = embedded + (embedded_ip->ihl * 4);
            if (embedded_ip->protocol == IPPROTO_TCP) {
                struct tcphdr *embedded_tcp = (struct tcphdr *)embedded_transport;
                std::cout << "    Original Source Port: " << ntohs(embedded_tcp->source) << std::endl;
                std::cout << "    Original Dest Port: " << ntohs(embedded_tcp->dest) << std::endl;
            } else if (embedded_ip->protocol == IPPROTO_UDP) {
                struct udphdr *embedded_udp = (struct udphdr *)embedded_transport;
                std::cout << "    Original Source Port: " << ntohs(embedded_udp->source) << std::endl;
                std::cout << "    Original Dest Port: " << ntohs(embedded_udp->dest) << std::endl;
            }
        }
    }

    std::cout << "====================================\n" << std::endl;
}
