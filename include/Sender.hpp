#ifndef SENDER_HPP
#define SENDER_HPP
#include <string>
#include <vector>

class Sender
{
public:
    Sender();
    void sendAll(const std::string& target_ip, const std::vector<unsigned short>& ports);
};

#endif
