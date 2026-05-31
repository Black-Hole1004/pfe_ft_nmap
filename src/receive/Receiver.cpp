#include "Receiver.hpp"
#include "functions.hpp"
#include <pcap.h>
#include <iostream>

Receiver::Receiver() {}

void Receiver::receiveAll(const std::string& target_ip)
{
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    std::string device = "";

    if (pcap_findalldevs(&alldevs, errorBuffer) == -1) {
        std::cout << "Error in pcap_findalldevs: " << errorBuffer << std::endl;
        return;
    }
    std::string preferred_interface = (target_ip == "127.0.0.1" || target_ip == "localhost") ? "lo" : "eth0";

    for (d = alldevs; d != NULL; d = d->next) {
        if (std::string(d->name) == preferred_interface) {
            device = d->name;
            break;
        }
    }

    if (device.empty()) {
        for (d = alldevs; d != NULL; d = d->next) {
            if (std::string(d->name) == "lo" || std::string(d->name) == "eth0") {
                device = d->name;
                break;
            }
        }
    }

    if (device.empty()) {
        std::cout << "No interfaces found." << std::endl;
        pcap_freealldevs(alldevs);
        return;
    }

    // opening device, params : name, snapshot length, promiscuous mode, timeout 1000ms, error buffer.
    pcap_t *handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errorBuffer);
    pcap_freealldevs(alldevs);

    if(!handle) {
        std::cout << "couldn't open device, " << errorBuffer << std::endl;
        return;
    }

    g_scan.handle = handle;
    g_scan.stop_pcap = false;
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

    int count = 50; // number of packets. -1 = infinite loop
    pcap_loop(g_scan.handle, count, packet_handler, nullptr);
    pcap_close(handle);
}
