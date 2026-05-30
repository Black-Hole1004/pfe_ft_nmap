#ifndef SYNSCAN_HPP
#define SYNSCAN_HPP

#include <string>
#include <vector>

class SynScan {
public:
    SynScan();
    ~SynScan();

    void run(const std::string& target_ip, const std::vector<unsigned short>& ports);
};

#endif