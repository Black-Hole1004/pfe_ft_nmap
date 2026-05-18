#include "Utils.hpp"
#include <regex>
#include <sstream>
#include <iostream>

Utils::Utils()
{
}

void Utils::noop()
{
}
#include "functions.hpp"

void error(int code, char *fmt, ...)
{
    (void)code;
    (void)fmt;
}

char *get_technique_name(t_technique technique)
{
    (void)technique;
    return (char *)"UNKNOWN";
}

void print_status_name(t_status status)
{
    (void)status;
}

void add_IP(t_IP addr)
{
    (void)addr;
}

void free_IPs()
{
}

int is_number(const std::string& str)
{
    if (str.empty())
        return 0;

    for (size_t i = 0; i < str.size(); i++) {
        if (!std::isdigit(str[i]))
            return 0;
    }

    return 1;
}
void check_down()
{
}

int get_number(char *str)
{
    (void)str;
    return -1;
}

bool isValidIP(const std::string& ip)
{
    std::regex pattern(
        R"(^(\d{1,3}\.){3}\d{1,3}$)"
    );

    return std::regex_match(ip, pattern);
}

 std::vector<unsigned short> split( const std::string &str, char del)
{
    std::vector<unsigned short> result;
    std::stringstream ss(str);

    std::string item;

    while (std::getline(ss, item, del)) {

        if(is_number(item))
        {
         unsigned short A = (unsigned short) std::stoi(item);
         result.push_back(A);
        }
        else
        std::cout << "error: " <<  item << " not a number."<<std::endl;

    }

    return result;
}