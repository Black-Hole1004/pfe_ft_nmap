#include "Parser.hpp"
#include "functions.hpp"

// constructor + init target to empty string
Parser::Parser() : target(""), ports(std::vector<unsigned short>()) 
{
}

// testing parsing, more flags later!
void Parser::parseArgs(int argc, char **argv)
{
    for(unsigned short i = 1; i < argc; i++){
        std::string curr = argv[i];
        if (curr == "--ip" && (i+1)<argc) { 
            target = argv[i+1]; 
            i++;
        } else if (curr[0] == '-') // flag
        {
            flag_parser(&i, argv, *this);
        }
        
    }
}

void flag_parser(unsigned short *index, char *argv[], Parser &p)
{
    std::string curr = argv[*index];

    if (curr == "-t") {
        std::cout << "test" << std::endl;
    } else if (curr == "-p") { // ports
        std::string portString = argv[*index + 1];

        try {
            unsigned short portUShort = std::stoi(portString);
            p.ports.push_back(portUShort); 
        } catch (...) {
            std::cerr << "Error: Invalid port number " << portString << std::endl;
        }

        *index += 1;
    }
}
