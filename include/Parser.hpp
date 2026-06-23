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
        std::vector<unsigned short> ports;
        int verbose;  // Changed from bool to int for multiple levels
        bool print_matrix;
        int thread_count;
        std::vector<std::string> scan_types;
};

#endif
