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

std::vector<unsigned short> split(
    const std::string& str,
    char delimiter
);
#endif
