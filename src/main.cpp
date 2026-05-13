#include "functions.hpp"
#include "Parser.hpp"

t_scan g_scan = {};

int main(int argc, char *argv[])
{
    Parser parser;
    parser.parseArgs(argc, argv);

    if (argc < 2) {
        std::cout << "Usage: ./pfe_ft_nmap" << std::endl;
        std::cout << "--ip <address-ipv4> / -t / -p <port>" << std::endl;
        return 1;
    }

    if(parser.target.empty()){
        std::cout << "empty" << std::endl;
    }

    std::cout << "target = " << parser.target << std::endl;
        
    return 0;
}
