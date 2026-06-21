#include "Parser.hpp"
#include "functions.hpp"
#include "Utils.hpp"

#include <string>
#include <iostream>

// constructor + init target to empty string
Parser::Parser() : target(""), ports(std::vector<unsigned short>()), verbose(false), print_matrix(false), thread_count(4)
{
}

// testing parsing, more flags later!
void Parser::parseArgs(int argc, char **argv)
{
    for (unsigned short i = 1; i < argc; i++) {
        std::string curr = argv[i];

        if (curr == "--ip") {
            if (argc <= (i+1) || argv[i+1][0] == '\0'){
                std::cout << ">>Error: --ip flag requires an arg." << std::endl;
                exit(1);
            }

            std::string arg = argv[i+1];

            if (isValidIP(arg)) {
                // IPv4 literal: normalize it
                target = sanitizeIP(arg);
            } else if (arg.find_first_not_of("0123456789.") == std::string::npos) {
                // Looks like an IPv4 address but is malformed
                std::cout << ">>Error: IP is invalid (IPV4 format: X.X.X.X, with X in 0-255)." << std::endl;
                exit(1);
            } else {
                // Accept hostname or IPv6 literal as-is; DNS resolution happens later
                target = arg;
            }
            i++;
        } else if (curr[0] == '-' && curr[1] != '-') {
            flag_parser(&i, argc, argv, *this);
        }
    }
}

void flag_parser(unsigned short *index,int argc, char *argv[], Parser &p) {
    std::string curr = argv[*index];

    if (curr == "-p")  {
        if ((*index + 1) >= argc || argv[*index + 1][0] == '\0') {
            std::cout << ">>Error: -p flag requires an arg." << std::endl;
            exit(1);
        }

        p.ports = split( argv[*index + 1],',');
        (*index )++;
    }
    else if(curr == "-v") {
        p.verbose = !p.verbose; // toggle
    }
    else if (curr == "-ctm") {
        p.print_matrix = true;
    }
    else if (curr == "-t") {
        if ((*index + 1) >= argc || argv[*index + 1][0] == '\0') {
            std::cout << ">>Error: -t flag requires an arg." << std::endl;
            exit(1);
        }
        if (!is_number(argv[*index + 1])) {
            std::cout << ">>Error: -t requires a number." << std::endl;
            exit(1);
        }
        int tc = std::stoi(argv[*index + 1]);
        if (tc < 1 || tc > 250) {
            std::cout << ">>Error: thread count must be between 1 and 250." << std::endl;
            exit(1);
        }
        p.thread_count = tc;
        (*index)++;
    }
    else if (curr == "-sA") { 
        p.scan_types.push_back("ACK");
    }
    else if (curr == "-sS") { 
        p.scan_types.push_back("SYN");
    }
    else if (curr == "-sF") { 
        p.scan_types.push_back("FIN");
    }
    else if (curr == "-sN") { 
        p.scan_types.push_back("NUL");
    }
    else if (curr == "-sX") { 
        p.scan_types.push_back("XMAS");
    }
    else if (curr == "-sU") { 
        p.scan_types.push_back("UDP");
    }
    else {
        std::cout << ">>Error: Unknown flag." << std::endl;
        exit(1);
    }
}
