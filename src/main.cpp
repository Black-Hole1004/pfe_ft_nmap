#include "functions.hpp"
#include "Parser.hpp"
#include "Receiver.hpp"

t_scan g_scan = {};

int main(int argc, char *argv[])
{
    Parser parser;
    parser.parseArgs(argc, argv);

    if (argc < 2) {
        std::cout << "Usage: ./pfe_ft_nmap --ip <address-ipv4> / -v / -p <port>" << std::endl;
        return 1;
    }

    if (parser.target.empty()) {
        std::cout << "Error: Target IP is mandatory!" << std::endl;
        return 1;
    } else {
        std::cout << "Target IP : " << parser.target << std::endl;
    }

    if (!parser.ports.empty()) {
      std::cout << "Ports: " << std::endl;

      // test receiver, dir ctl+c bach tkhroj -----------------------------
        Receiver receiver;
        std::cout << "Receiving... #CTRL+C to exit" << std::endl;
        receiver.receiveAll();
      // endtest ----------------------------------------------------------

      for (size_t i = 0; i < parser.ports.size(); i++)
      {
        std::cout << parser.ports[i] << std::endl;
      }
    }  
    else
    std::cout << " no ports" << std::endl;
    
    
    if(parser.verbose == true)
    {std::cout << " verbose on" << std::endl;}
    
    else
    {std::cout << " verbose off" << std::endl;}

     return 0;
}