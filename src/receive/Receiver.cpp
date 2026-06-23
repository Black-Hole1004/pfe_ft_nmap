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

    // Receive responses with adaptive timeout
    if (g_scan.options.verbose)
        std::cout << "Waiting for responses..." << std::endl;

    struct timeval start, now, last_packet;
    gettimeofday(&start, NULL);
    last_packet = start;

    int expected_responses = g_scan.options.port_count * g_scan.options.technique_count * g_scan.ip_count;
    int received_count = 0;
    int prev_received = 0;

    const double MAX_TOTAL_TIMEOUT = 15.0;      // Maximum total wait time
    const double IDLE_TIMEOUT = 2.0;             // Exit if no packets for 2 seconds
    const double MIN_WAIT = 0.5;                 // Minimum wait time (for slow networks)

    while (!g_scan.stop_pcap) {
        int packets = pcap_dispatch(g_scan.handle, -1, packet_handler, NULL);

        if (packets > 0) {
            gettimeofday(&last_packet, NULL);
            received_count += packets;
        }

        gettimeofday(&now, NULL);
        double total_elapsed = (now.tv_sec - start.tv_sec) + (now.tv_usec - start.tv_usec) / 1000000.0;
        double idle_time = (now.tv_sec - last_packet.tv_sec) + (now.tv_usec - last_packet.tv_usec) / 1000000.0;

        // Exit conditions:
        // 1. All expected responses received (unlikely for filtered ports)
        // 2. No packets received for IDLE_TIMEOUT seconds (after MIN_WAIT)
        // 3. Maximum timeout reached
        if (total_elapsed >= MAX_TOTAL_TIMEOUT)
            break;

        if (total_elapsed >= MIN_WAIT && idle_time >= IDLE_TIMEOUT)
            break;

        usleep(10000); // 10ms to avoid busy-waiting

        // Track if we're still receiving packets
        if (received_count != prev_received) {
            prev_received = received_count;
        }
    }

    if (g_scan.options.verbose)
        std::cout << std::endl;
}
