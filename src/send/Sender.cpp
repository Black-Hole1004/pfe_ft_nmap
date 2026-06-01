#include "Sender.hpp"
#include "functions.hpp"
#include <iostream>

Sender::Sender()
{
}

void Sender::sendAll(const std::string& target_ip, const std::vector<unsigned short>& ports) {
    (void)target_ip;
    (void)ports;
    std::cout << "Activating sender..." << std::endl;
    init_send();
    thread_send();
}
