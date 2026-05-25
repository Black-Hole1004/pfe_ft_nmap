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

bool isValidIP(const std::string &ip)
{
    std::stringstream ss(ip);
    std::string segment;
    std::vector<int> segments;

    while (std::getline(ss, segment, '.')) {
        // empty or non-digit chars
        if(segment.empty() || segment.find_first_not_of("0123456789") != std::string::npos) {
            return false;
        }

        // octet in 0-255
        int value = std::stoi(segment);
        if (value < 0 || value > 255) {
            return false;
        }

        segments.push_back(value);
    }
    // only return true if segments has 4 elements
    return segments.size() == 4;
}

std::string sanitizeIP(const std::string &IP) {
    std::stringstream ss(IP);
    std::string octet;
    std::string cleanIP = "";
    int count = 0;

    while (std::getline(ss, octet, '.')) {
        size_t first_non_zero = octet.find_first_not_of('0');

        if (first_non_zero == std::string::npos) {
            octet = "0";
        } else {
            octet = octet.substr(first_non_zero);
        }

        // Rebuild the IP string with dots
        if (count > 0) {
            cleanIP += ".";
        }
        cleanIP += octet;
        count++;
    }

    return cleanIP;
}

std::vector<unsigned short> split( const std::string &str, char del) {
    std::vector<unsigned short> result;
    std::stringstream ss(str);
    std::string item;

    while (std::getline(ss, item, del)) {
        if(is_number(item)) {
            unsigned int parsedValue = std::stoi(item);

            if (parsedValue >= 65535 ) {
                std::cout << ">>Error: Port" << parsedValue << " out of bounds (0-65535)." << std::endl;
                exit(1);
            }

            unsigned short A = static_cast<unsigned short>(parsedValue);
            result.push_back(A);
        } else {
            std::cout << "error: " <<  item << " not a number."<<std::endl;
            exit(1);
        }
    }

    return result;
}