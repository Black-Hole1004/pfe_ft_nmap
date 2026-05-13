#include "functions.hpp"
#include "Parser.hpp"

t_scan g_scan = {};

int main(int argc, char *argv[])
{
    Parser parser;
    parser.parseArgs(argc, argv);

    if (argc < 2) {
        std::cout << "Usage: ./pfe_ft_nmap --ip <address-ipv4> / -t / -p <port>" << std::endl;
        return 1;
    }

    if (parser.target.empty()) {
        std::cout << "Error: Target IP is mandatory!" << std::endl;
        return 1;
    } else {
        std::cout << "Target IP : " << parser.target << std::endl;
    }

    if (!parser.ports.empty()) {
        std::cout << "Port Range: " << parser.ports << std::endl;
    }
    return 0;
}