#include "scanner.hpp"
#include "Sender.hpp"
#include "Receiver.hpp"
#include "types.hpp"
#include "functions.hpp"
#include <iostream>
#include <iomanip>

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
            if (g_scan.options.technique[t]){
                for_each_port([&](unsigned short port) {
                    ip->status[t][port] = FILTERED;
                    if (t == FIN || t == NUL || t == XMAS || t == UDP)
                        ip->status[t][port] = static_cast<t_status>(ip->status[t][port] | OPEN);
                });
            }
    }

    std::cout << "\n--- Starting Scan ---" << std::endl;

    // Send all packets (blocking)
    Sender sender;
    sender.sendAll(target_ip, ports);

    // Capture responses via the Receiver module
    Receiver receiver;
    receiver.receiveAll(target_ip);

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
                std::cout << "--------------------------\n";
            }
    }
}

void Scanner::printSummaryMatrix(const std::vector<unsigned short>& ports)
{
    auto status_to_str = [](t_status st) -> std::string {
        if (st == CLOSED) return "closed";
        if (st == OPEN) return "open";
        if (st == FILTERED) return "filtered";
        if (st == static_cast<t_status>(OPEN | FILTERED)) return "open|filtered";
        if (st == UNFILTERED) return "unfiltered";
        return "unknown";
    };

    // Extract active ports
    std::vector<unsigned short> active_ports;
    if (!ports.empty()) {
        active_ports = ports;
    } else {
        for (int p = 0; p <= USHRT_MAX; p++)
            if (g_scan.options.port[p])
                active_ports.push_back(p);
    }

    if (active_ports.empty()) return;

    // Extract active techniques
    std::vector<int> active_techniques;
    for (int t = 0; t < TECHNIQUE_COUNT; t++)
        if (g_scan.options.technique[t])
            active_techniques.push_back(t);

    if (active_techniques.empty()) return;

    const int padding = 2;

    // Compute PORT column width
    int port_col_width = 4; // "PORT"
    for (unsigned short port : active_ports) {
        std::string label = std::to_string(port) + "/tcp";
        if (port_col_width < (int)label.length())
            port_col_width = label.length();
    }
    port_col_width += padding;

    // Compute technique column widths
    std::vector<int> tech_col_widths(active_techniques.size(), 0);
    for (size_t i = 0; i < active_techniques.size(); ++i) {
        int t = active_techniques[i];
        std::string tech_name = get_technique_name(static_cast<t_technique>(t));
        tech_col_widths[i] = (int)tech_name.length() + padding;

        for (t_IP *ip = g_scan.ip; ip; ip = ip->next) {
            if (ip->is_down) continue;
            for (unsigned short port : active_ports) {
                int w = (int)status_to_str(ip->status[t][port]).length() + padding;
                if (tech_col_widths[i] < w)
                    tech_col_widths[i] = w;
            }
        }
    }

    // Print one matrix per target IP
    for (t_IP *ip = g_scan.ip; ip; ip = ip->next) {
        if (ip->is_down) continue;

        std::cout << "\n==================================================\n";
        std::cout << "  Cross-technique matrix for " << ip->name << "\n";
        std::cout << "==================================================\n";

        // Header row
        std::cout << std::left << std::setw(port_col_width) << "PORT";
        for (size_t i = 0; i < active_techniques.size(); ++i) {
            int t = active_techniques[i];
            std::cout << std::left << std::setw(tech_col_widths[i])
                      << get_technique_name(static_cast<t_technique>(t));
        }
        std::cout << "\n";

        // Separator
        std::cout << std::string(port_col_width, '-');
        for (int w : tech_col_widths)
            std::cout << std::string(w, '-');
        std::cout << "\n";

        // One row per port
        for (unsigned short port : active_ports) {
            std::string port_label = std::to_string(port) + "/tcp";
            std::cout << std::left << std::setw(port_col_width) << port_label;

            for (size_t i = 0; i < active_techniques.size(); ++i) {
                int t = active_techniques[i];
                std::cout << std::left << std::setw(tech_col_widths[i])
                          << status_to_str(ip->status[t][port]);
            }
            std::cout << "\n";
        }

        // Separator
        std::cout << std::string(port_col_width, '-');
        for (int w : tech_col_widths)
            std::cout << std::string(w, '-');
        std::cout << "\n";
    }
}
