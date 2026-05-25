#include "Receiver.hpp"
#include "functions.hpp"
#include <pcap.h>
#include <iostream>


Receiver::Receiver() {}

void Receiver::receiveAll()
{
    char errorBuffer[PCAP_ERRBUF_SIZE];

    char *device = pcap_lookupdev(errorBuffer);
    if(!device) {
        std::cout << "no device found, " << errorBuffer << std::endl;
        return;
    }

    // opening device, params : name, snapshot length, promiscuous mode, timeout 1000ms, error buffer.
    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, errorBuffer);
    if(!handle) {
        std::cout << "couldn't open device, " << errorBuffer << std::endl;
        return;
    }

    // filter traffic
    struct bpf_program filter;
    std::string filterString = "tcp"; // cpp string, converted to C "string" with std::c_str()

    if(pcap_compile(handle, &filter, filterString.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
       pcap_setfilter(handle, &filter) == -1)
    {
        std::cout << "couldn't set filter" << std::endl;
        return;
    }

    std::cout << "listening on " << device << std::endl;

    int count = -1; // number of packets. -1 = infinite loop
    pcap_loop(handle, count, packet_handler, nullptr);
    pcap_close(handle);
}
