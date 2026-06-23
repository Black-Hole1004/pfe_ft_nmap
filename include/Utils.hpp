#ifndef UTILS_HPP
#define UTILS_HPP
#include <string>
#include <vector>
class Utils
{
public:
    Utils();
    void noop();
};

bool isValidIP(const std::string& ip);
std::string sanitizeIP(const std::string &IP);
bool isValidCIDR(const std::string& cidr);
std::vector<std::string> expandCIDR(const std::string& cidr);

std::vector<unsigned short> split(
    const std::string& str,
    char delimiter
);
#endif
