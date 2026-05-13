#ifndef PARSER_HPP
#define PARSER_HPP

#include <string>
#include <iostream>
#include <vector>

class Parser
{
public:
    Parser();
    void parseArgs(int argc, char **argv);

    std::string target;
};

#endif
