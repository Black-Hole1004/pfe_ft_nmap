#include "Receiver.hpp"
#include "functions.hpp"
#include "types.hpp"
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <sys/time.h>
#include <unistd.h>

Receiver::Receiver() {}

void Receiver::receiveAll(const std::string& target_ip)
{
    (void)target_ip;

    // Set pcap to non-blocking so we can poll with a manual timeout
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_setnonblock(g_scan.handle, 1, errbuf) == -1)
        std::cerr << "pcap_setnonblock: " << errbuf << std::endl;

    // Receive responses with manual timeout (15 seconds)
    std::cout << "Waiting for responses..." << std::endl;
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (!g_scan.stop_pcap) {
        pcap_dispatch(g_scan.handle, -1, packet_handler, NULL);

        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_usec - start.tv_usec) / 1000000.0;
        if (elapsed >= 15.0)
            break;

        usleep(10000); // 10ms to avoid busy-waiting
    }

    if (g_scan.options.verbose)
        std::cout << std::endl;
}
