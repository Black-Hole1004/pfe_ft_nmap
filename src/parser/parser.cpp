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

        if (curr == "--ip" && (i + 1) < argc && !std::string(argv[i + 1]).empty() && isValidIP(argv[i + 1]) ) {
            target = argv[i + 1];
            i++;
        } else if (curr[0] == '-') // flag
        {
            flag_parser(&i, argc,argv, *this);
        }
    }
}

void flag_parser(unsigned short *index,int argc, char *argv[], Parser &p)
{
    std::string curr = argv[*index];

    if (curr == "-t") 
    {
        std::cout << "test" << std::endl;
    }
    else if (curr == "-p" && (*index + 1) < argc &&!std::string(argv[*index + 1]).empty())  
    {
        p.ports = split( argv[*index + 1],',');
        (*index )++;
    }
    else if(curr == "-v")
    {
        p.verbose=true;
    }
    else
    std::cout << "syntax error" << std::endl;
}