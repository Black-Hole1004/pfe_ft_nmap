#include "functions.hpp"
#include "Parser.hpp"
#include "Receiver.hpp"
#include "Sender.hpp"
#include "syn_scan.hpp"

t_scan g_scan = {};
u_int8_t g_port_results[65636] = {0};

int main(int argc, char *argv[]) {
  
	if (argc < 2) {
		std::cout << "Usage: ./pfe_ft_nmap --ip <address-ipv4> / -v / -p <port>" << std::endl;
		return 1;
	}
	Parser parser;
	parser.parseArgs(argc, argv);
	
	std::cout << "Target IP : " << parser.target << std::endl;

	if (!parser.ports.empty()) {
		std::cout << "Ports: ";

		for (size_t i = 0; i < parser.ports.size(); i++) {
			std::cout << parser.ports[i] << std::endl;
		}

		SynScan scanner;
		scanner.run(parser.target, parser.ports);
	}  
	else std::cout << " no ports specified." << std::endl;


	if(parser.verbose == true)
	{std::cout << " verbose on" << std::endl;}
	else
	{std::cout << " verbose off" << std::endl;}

	return 0;
}