#include "Receiver.hpp"
#include "functions.hpp"
#include <pcap.h>
#include <iostream>
#include <cstring>

Receiver::Receiver() {}

void Receiver::receiveAll(const std::string& target_ip)
{
    (void)target_ip;
    // pcap handle is managed externally (opened in main)
    // This class is kept for compatibility but the actual receive loop
    // lives in syn_scan.cpp / main.cpp to match ft_nmap's flow.
    (void)target_ip;
}
