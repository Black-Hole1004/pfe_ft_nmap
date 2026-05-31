#ifndef RECEIVER_HPP
#define RECEIVER_HPP

#include <string>

class Receiver
{
public:
    Receiver();
    void receiveAll(const std::string& target_ip);
};

#endif
