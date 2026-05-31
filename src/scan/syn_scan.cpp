#include "syn_scan.hpp"
#include "Sender.hpp"
#include "Receiver.hpp"
#include "types.hpp"
#include <pthread.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>

SynScan::SynScan() {}
SynScan::~SynScan() {}
std::string target;

void* run_receiver_thread(void* arg) {
    Receiver* receiver = static_cast<Receiver*>(arg);
    receiver->receiveAll(target);
    return nullptr;
}

void SynScan::run(const std::string& target_ip, const std::vector<unsigned short>& ports) {
    pthread_t bg_receiver_thread;
    Receiver receiver;
    Sender sender;
    target = target_ip;

    for (unsigned short port : ports) {
        g_port_results[port] = STATE_FILTERED;
    }

    std::cout << "\n--- Starting SYN Scan ---" << std::endl;


    std::cout << "[Scanner] Initializing background sniffer..." << std::endl;
    if (pthread_create(&bg_receiver_thread, NULL, run_receiver_thread, &receiver) != 0) {
        std::cout << ">>Error: Failed to spin up background sniffing thread." << std::endl;
        return;
    }

    usleep(1000000);

    std::cout << "[Scanner] Handing execution to worker dispatch..." << std::endl;
    sender.sendAll(target_ip, ports);

    sleep(2); 
    if (g_scan.handle != NULL) {
        g_scan.stop_pcap = true;
        pcap_breakloop(g_scan.handle); 
    }

    std::cout << "[Scanner] Scan execution finalized." << std::endl;
    pthread_join(bg_receiver_thread, NULL);

    std::cout << "Nmap scan report for " << target_ip << "\n";
    std::cout << "PORT      STATE    SERVICE\n";
    std::cout << "--------------------------\n";

    for (unsigned short port : ports) {
        std::string state_str = "filtered";
        
        if (g_port_results[port] == STATE_OPEN) {
            state_str = "open";
        } else if (g_port_results[port] == STATE_CLOSED) {
            state_str = "closed";
        }

        std::cout << std::left << std::setw(10) << (std::to_string(port) + "/tcp")
                  << std::setw(9)  << state_str
                  << "unknown" << std::endl; 
    }
}