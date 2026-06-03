#include "scanner.hpp"
#include "Sender.hpp"
#include "Receiver.hpp"
#include "types.hpp"
#include "functions.hpp"
#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <sys/time.h>

Scanner::Scanner() {}
Scanner::~Scanner() {}

void Scanner::run(const std::string& target_ip, const std::vector<unsigned short>& ports)
{
    (void)target_ip;

    // Helper to iterate either over the vector or over the global port array
    auto for_each_port = [&](auto&& fn) {
        if (!ports.empty()) {
            for (unsigned short port : ports)
                fn(port);
        } else {
            for (int port = 0; port <= USHRT_MAX; port++)
                if (g_scan.options.port[port])
                    fn(port);
        }
    };

    // Initialize default statuses
    for (t_IP *ip = g_scan.ip; ip; ip = ip->next)
    {
        if (ip->is_down)
            continue;
        for (int t = 0; t < TECHNIQUE_COUNT; t++)
            if (g_scan.options.technique[t])
                for_each_port([&](unsigned short port) {
                    ip->status[t][port] = FILTERED;
                    if (t == FIN || t == NUL || t == XMAS || t == UDP)
                        ip->status[t][port] = static_cast<t_status>(ip->status[t][port] | OPEN);
                });
    }

    std::cout << "\n--- Starting Scan ---" << std::endl;

    // Send all packets (blocking)
    Sender sender;
    sender.sendAll(target_ip, ports);

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

    std::cout << "[Scanner] Scan execution finalized." << std::endl;

    // Print results
    for (t_IP *ip = g_scan.ip; ip; ip = ip->next) {
        if (ip->is_down)
            continue;

        std::cout << "\nNmap scan report for " << ip->name << "\n";
        for (int t = 0; t < TECHNIQUE_COUNT; t++)
            if (g_scan.options.technique[t]) {
                std::cout << get_technique_name(static_cast<t_technique>(t)) << " scan results:\n";
                std::cout << "PORT\t\tSTATE\n";
                std::cout << "--------------------------\n";

                for_each_port([&](unsigned short port) {
                    t_status st = ip->status[t][port];
                    std::string state;
                    if (st == FILTERED) state = "filtered";
                    else if (st == OPEN) state = "open";
                    else if (st == CLOSED) state = "closed";
                    else if (st == static_cast<t_status>(OPEN | FILTERED)) state = "open|filtered";
                    else if (st == UNFILTERED) state = "unfiltered";
                    else state = "unknown";

                    std::cout << std::left << std::setw(10) << (std::to_string(port) + "/tcp")
                              << std::setw(12) << state << std::endl;

                    if (st == OPEN) g_port_results[port] = STATE_OPEN;
                    else if (st == CLOSED) g_port_results[port] = STATE_CLOSED;
                    else g_port_results[port] = STATE_FILTERED;
                });
            }
    }
}

void Scanner::printSummaryMatrix(const std::vector<unsigned short>& ports)
{
    // Local lambda utility to extract active target ports safely
    auto get_active_ports = [&](std::vector<unsigned short>& list) {
        if (!ports.empty()) {
            list = ports;
        } else {
            for (int p = 0; p <= USHRT_MAX; p++)
                if (g_scan.options.port[p])
                    list.push_back(p);
        }
    };

    std::vector<unsigned short> active_ports;
    get_active_ports(active_ports);

    if (active_ports.empty()) return;

    // Define fixed width spacing configurations
    const int row_label_width = 15;
    const int col_width = 15;

    for (t_IP *ip = g_scan.ip; ip; ip = ip->next) 
    {
        if (ip->is_down) continue;

        std::cout << "\n====================================================================\n";
        std::cout << "                 CROSS-TECHNIQUE MATRIX FOR " << ip->name << "\n";
        std::cout << "====================================================================\n\n";

        // 1. PRINT HEADER (Ports Columns)
        std::cout << std::left << std::setw(row_label_width) << ""; 
        for (unsigned short port : active_ports) {
            std::cout << std::left << std::setw(col_width) << ("Port " + std::to_string(port));
        }
        std::cout << "\n";

        // 2. PRINT TOP BORDER LINE
        std::cout << std::left << std::setw(row_label_width) << "";
        for (size_t i = 0; i < active_ports.size(); ++i) {
            std::cout << std::left << std::setw(col_width) << "-------------";
        }
        std::cout << "\n";

        // 3. PRINT ROWS (Techniques Loop)
        for (int t = 0; t < TECHNIQUE_COUNT; t++) 
        {
            // Only print rows for techniques that were actually requested/run
            if (!g_scan.options.technique[t]) continue; 

            // Format row prefix label: e.g., "SYN (Index 1)"
            std::string label = get_technique_name(static_cast<t_technique>(t)) + std::string(" (Index ") + std::to_string(t) + ")";
            std::cout << std::left << std::setw(row_label_width) << label;

            // Print status value for every port in this row
            for (unsigned short port : active_ports) 
            {
                t_status st = ip->status[t][port];
                std::string state_str;

                if (st == CLOSED) state_str = "CLOSED";
                else if (st == OPEN) state_str = "OPEN";
                else if (st == FILTERED) state_str = "FILTERED";
                else if (st == static_cast<t_status>(OPEN | FILTERED)) state_str = "OPEN|FILTERED";
                else if (st == UNFILTERED) state_str = "UNFILTERED";
                else state_str = "UNKNOWN";

                std::cout << std::left << std::setw(col_width) << state_str;
            }
            std::cout << "\n";
        }

        // 4. PRINT BOTTOM BORDER LINE
        std::cout << std::left << std::setw(row_label_width) << "";
        for (size_t i = 0; i < active_ports.size(); ++i) {
            std::cout << std::left << std::setw(col_width) << "-------------";
        }
        std::cout << "\n\n";
    }
}