#include "Parser.hpp"
#include "functions.hpp"
#include "Utils.hpp"

#include <string>
#include <iostream>

// constructor + init target to empty string
Parser::Parser() : target(""), ports(std::vector<unsigned short>()) ,verbose(false)
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

            if(!isValidIP(argv[i+1])) {
                std::cout << ">>Error: IP is invalid (IPV4 format: X.X.X.X)." << std::endl;
                exit(1);
            }
            // checks passed = valid ip registered.
            target = argv[i + 1];
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
    else {
        std::cout << ">>Error: Unknown flag." << std::endl;
        exit(1);
    }
}