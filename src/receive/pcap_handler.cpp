#include "functions.hpp"

void packet_handler(unsigned char *user, const struct pcap_pkthdr *hdr, const unsigned char *data)
{
    (void)user;
    (void)hdr;
    
    struct ip *ipHeader = (struct ip *)(data + 14); // 14 bytes = ethernet header
    if(ipHeader->ip_p == IPPROTO_TCP) {
        int ipLength = ipHeader->ip_hl * 4; // ip header
        struct tcphdr *tcp = (struct tcphdr *)(data + 14 + ipLength); // data = raw bytes (char*) => cast + skip headers.
        
        // ntohs = network to host short.
        unsigned int sourcePort = ntohs(tcp->th_sport);
        std::cout << "#TCP_PACKET From port: " << sourcePort << ", Flags: " << (int)tcp->th_flags <<  std::endl;

        if((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) // TH_SYN = synchronize, TH_ACK = acknowledge.
        // check with '&' bitwise AND
        {
            std::cout << "Port: " << sourcePort << " is open." << std::endl; 
        }
    } else if(ipHeader->ip_p == IPPROTO_ICMP) {
        std::cout << "#ICMP_PACKET --" << std::endl;
    }
}
