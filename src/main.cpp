#include "functions.hpp"
#include "Parser.hpp"

t_scan g_scan = {};

int main(int argc, char *argv[])
{
    Parser parser;
    parser.parseArgs(argc, argv);

    if(parser.target.empty()){
        std::cout << "empty" << std::endl;
    } else {
        std::cout << "target = " << parser.target << std::endl;
    }
    return 0;
}
