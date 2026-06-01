#include "functions.hpp"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

static void icmp_analyze(int technique, int port, struct icmphdr *icmp, t_IP *IP)
{
    if (icmp->type != ICMP_UNREACH)
        return;

    if (icmp->code != ICMP_UNREACH_HOST &&
        icmp->code != ICMP_UNREACH_PROTOCOL &&
        icmp->code != ICMP_UNREACH_PORT &&
        icmp->code != ICMP_UNREACH_NET_PROHIB &&
        icmp->code != ICMP_UNREACH_HOST_PROHIB &&
        icmp->code != ICMP_UNREACH_FILTER_PROHIB)
        return;

    if (technique == UDP && icmp->code == ICMP_UNREACH_PORT)
        IP->status[technique][port] = CLOSED;
    else
        IP->status[technique][port] = FILTERED;
}

void packet_handler(unsigned char *arg, const struct pcap_pkthdr *pcap_header, const unsigned char *data)
{
    (void)arg;
    (void)pcap_header;

    int linkType = pcap_datalink(g_scan.handle);
    int offset = 14; // ethernet
    if (linkType == DLT_LINUX_SLL)
        offset = 16;
    else if (linkType == DLT_NULL)
        offset = 4;

    data += offset;

    int ip_size = g_scan.options.family == AF_INET ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);
    t_packet_header *header = (t_packet_header *)data;
    t_packet_header *packet = (t_packet_header *)(data + ip_size);
    uint8_t protocol = g_scan.options.family == AF_INET ? header->ipv4.protocol : header->ipv6.ip6_nxt;

    // Match source IP to a target IP
    t_IP *IP = nullptr;
    for (IP = g_scan.ip; IP; IP = IP->next)
        if (g_scan.options.family == AF_INET && IP->addr.ipv4.sin_addr.s_addr == header->ipv4.saddr)
            break;
        else if (g_scan.options.family == AF_INET6 && !std::memcmp(&IP->addr.ipv6.sin6_addr, &header->ipv6.ip6_src, sizeof(struct in6_addr)))
            break;
    if (!IP)
        return;

    int technique;
    int port;
    if (protocol == IPPROTO_ICMP)
    {
        data += sizeof(struct icmphdr) + ip_size; // go to old packet
        protocol = g_scan.options.family == AF_INET ? ((struct iphdr *)data)->protocol
                                            : ((struct ip6_hdr *)data)->ip6_nxt;

        t_packet_header *packet_old = (t_packet_header *)(data + ip_size);
        technique = protocol == IPPROTO_TCP ? ntohs(packet_old->tcp.source) : ntohs(packet_old->udp.source);
        port = protocol == IPPROTO_TCP ? ntohs(packet_old->tcp.dest) : ntohs(packet_old->udp.dest);

        // Validate technique to ignore spurious ICMPs
        if (technique < 0 || technique >= TECHNIQUE_COUNT || !g_scan.options.technique[technique])
            return;

        icmp_analyze(technique, port, &packet->icmp, IP);
    }
    else
    {
        technique = protocol == IPPROTO_TCP ? ntohs(packet->tcp.dest) : ntohs(packet->udp.dest);
        port = protocol == IPPROTO_TCP ? ntohs(packet->tcp.source) : ntohs(packet->udp.source);

        // Validate technique: ignore outgoing packets (where technique would be a port number > 5)
        if (technique < 0 || technique >= TECHNIQUE_COUNT || !g_scan.options.technique[technique])
            return;

        if (technique == UDP || packet->tcp.syn)
            IP->status[technique][port] = OPEN;
        else if (packet->tcp.rst)
            IP->status[technique][port] = technique == ACK ? UNFILTERED : CLOSED;
    }

    if (g_scan.options.verbose)
    {
        static int amount = 0;
        std::cout << "\rReceived " << ++amount << " out of " << (g_scan.options.port_count * g_scan.options.technique_count * g_scan.ip_count)
                  << ". Waiting for additional responses..." << std::flush;
    }
}
