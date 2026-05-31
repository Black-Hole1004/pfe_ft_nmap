#include "functions.hpp"

void packet_handler(unsigned char *user, const struct pcap_pkthdr *hdr, const unsigned char *data)
{
    (void)user;
    (void)hdr;
    
    int linkType = pcap_datalink(g_scan.handle);
    int offset = 14; // (eth0)
    if (linkType == DLT_LINUX_SLL) {
        offset = 16;
    }
    struct ip *ipHeader;
    if (linkType == DLT_NULL) {
        offset = 4;
        uint32_t family = *(const uint32_t *)data;
        if (family != AF_INET && family != 2) {
            return;
        }
    }
    ipHeader = (struct ip *)(data + offset);

    if(ipHeader->ip_p == IPPROTO_TCP) {
        int ipLength = ipHeader->ip_hl * 4; // ip header
        struct tcphdr *tcp = (struct tcphdr *)(data + offset + ipLength); // data = raw bytes (char*) => cast + skip headers.
        
        // ntohs = network to host short.
        unsigned int sourcePort = ntohs(tcp->th_sport);
        unsigned int destPort = ntohs(tcp->th_dport);
        unsigned int flags = tcp->th_flags;
        std::cout << "#TCP_PACKET From port: " << sourcePort << ", Flags: " << (int)tcp->th_flags <<  std::endl;

        if((flags & TH_SYN) && (flags & TH_ACK)) {
            std::cout << " -> Port " << sourcePort << " is OPEN" << std::endl;
            g_port_results[sourcePort] = STATE_OPEN;
        } 
        else if (flags & TH_RST) {
            std::cout << " -> Port " << sourcePort << " is CLOSED" << std::endl;
            g_port_results[sourcePort] = STATE_CLOSED;
        }

    } else if(ipHeader->ip_p == IPPROTO_ICMP) {
        std::cout << "#ICMP_PACKET --" << std::endl;
    }
}
