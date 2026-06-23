#include "functions.hpp"
#include "Parser.hpp"
#include "Receiver.hpp"
#include "Sender.hpp"
#include "scanner.hpp"
#include "Utils.hpp"

#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <cstring>
#include <arpa/inet.h>

t_scan g_scan = {};
u_int8_t g_port_results[65536] = {0};

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        std::cerr << "You need to be root to run this program" << std::endl;
        return 1;
    }

    if (argc < 2) {
        std::cout << "Usage: ./pfe_ft_nmap --ip <address|hostname|CIDR> -p <port1,port2,...> -[sS|sF|sN|sX|sA|sU] [-t <threads>] [-ctm]" << std::endl;
        return 1;
    }

    Parser parser;
    parser.parseArgs(argc, argv);

    if (parser.target.empty()) {
        std::cerr << "No target specified" << std::endl;
        return 1;
    }

    g_scan.options.family = AF_INET;
    g_scan.options.thread_count = parser.thread_count;
    g_scan.options.verbose = parser.verbose;

    if (g_scan.options.verbose)
        std::cout << "Target : " << parser.target << std::endl;

    // Check if target is CIDR notation
    if (isValidCIDR(parser.target)) {
        std::vector<std::string> ips = expandCIDR(parser.target);
        if (g_scan.options.verbose)
            std::cout << "Expanding CIDR to " << ips.size() << " hosts..." << std::endl;
        for (const std::string& ip_str : ips) {
            t_IP target = resolve_target(ip_str);
            add_IP(target);
        }
    } else {
        // Resolve target (IPv4/IPv6 literal or hostname via DNS)
        t_IP target = resolve_target(parser.target);
        add_IP(target);
    }

    // Get interface
    g_scan.interface = get_interface();

    // Setup ports
    if (!parser.ports.empty()) {
        for (unsigned short p : parser.ports) {
            g_scan.options.port[p] = true;
            g_scan.options.port_count++;
        }
    } else {
        /* for (int p = PORT_MIN; p <= PORT_MAX; p++) {
            g_scan.options.port[p] = true;
            g_scan.options.port_count++;
        } */
        for (int p = PORT_MIN; p <= 10; p++) {
            g_scan.options.port[p] = true;
            g_scan.options.port_count++;
        }
    }

    // Setup techniques (default SYN only for now)
    std::memset(g_scan.options.technique, 0, sizeof(g_scan.options.technique));
    g_scan.options.technique_count = 0;

    if (!parser.scan_types.empty()) {
        for (const std::string& type : parser.scan_types) {
            if (type == "ACK" && !g_scan.options.technique[ACK]) {
                g_scan.options.technique[ACK] = true;
                g_scan.options.technique_count++;
            }
            else if (type == "SYN" && !g_scan.options.technique[SYN]) {
                g_scan.options.technique[SYN] = true;
                g_scan.options.technique_count++;
            }
            else if (type == "FIN" && !g_scan.options.technique[FIN]) {
                g_scan.options.technique[FIN] = true;
                g_scan.options.technique_count++;
            }
            else if (type == "NUL" && !g_scan.options.technique[NUL]) {
                g_scan.options.technique[NUL] = true;
                g_scan.options.technique_count++;
            }
            else if (type == "XMAS" && !g_scan.options.technique[XMAS]) {
                g_scan.options.technique[XMAS] = true;
                g_scan.options.technique_count++;
            }
            else if (type == "UDP" && !g_scan.options.technique[UDP]) {
                g_scan.options.technique[UDP] = true;
                g_scan.options.technique_count++;
            }
        }
    } else {
        // Fallback default if no scan flags are provided
        g_scan.options.technique[SYN] = true;
        g_scan.options.technique_count = 1;
    }

    // exclusive scans : 
    

    // Clamp thread count
    if (g_scan.options.thread_count < g_scan.options.technique_count)
        g_scan.options.thread_count = g_scan.options.technique_count;

    if (g_scan.options.thread_count > g_scan.options.port_count * g_scan.options.technique_count)
        g_scan.options.thread_count = g_scan.options.port_count * g_scan.options.technique_count;
    if (g_scan.options.thread_count == 0)
        g_scan.options.thread_count = 1;

    // Determine resolved IP string to choose the correct pcap device
    std::string resolved_ip;
    for (t_IP *ip = g_scan.ip; ip != NULL; ip = ip->next) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        inet_ntop(g_scan.options.family,
                  g_scan.options.family == AF_INET ? (void*)&ip->addr.ipv4.sin_addr : (void*)&ip->addr.ipv6.sin6_addr,
                  ip_str, sizeof(ip_str));
        resolved_ip = ip_str;
        break;
    }

    // Find pcap device
    std::string device = find_pcap_device(resolved_ip);
    if (device.empty()) {
        std::cerr << "No suitable pcap device found" << std::endl;
        return 1;
    }

    // Open pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    g_scan.handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!g_scan.handle) {
        std::cerr << "pcap_open_live: " << errbuf << std::endl;
        return 1;
    }

    // Build and set pcap filter: host <target>
    char filter[BUFSIZ] = {0};
    for (t_IP *ip = g_scan.ip; ip != NULL; ip = ip->next) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        inet_ntop(g_scan.options.family,
                  g_scan.options.family == AF_INET ? (void*)&ip->addr.ipv4.sin_addr : (void*)&ip->addr.ipv6.sin6_addr,
                  ip_str, sizeof(ip_str));
        std::strcat(filter, "host ");
        std::strcat(filter, ip_str);
        if (ip->next)
            std::strcat(filter, " or ");
    }
    if (g_scan.options.verbose)
        std::cout << "Filter: " << filter << std::endl;

    struct bpf_program fp = {0};
    if (pcap_compile(g_scan.handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(g_scan.handle, &fp) == -1) {
        std::cerr << "Failed to set pcap filter" << std::endl;
        return 1;
    }
    pcap_freecode(&fp);

    // Run scan
    Scanner scanner;
    scanner.run(parser.target, parser.ports);

    // Optionally print the cross-technique matrix
    if (parser.print_matrix)
        scanner.printSummaryMatrix(parser.ports);

    pcap_close(g_scan.handle);
    free_IPs();

    return 0;
}
