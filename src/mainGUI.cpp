#include "functions.hpp"
#include "gui_widgets.hpp"
#include <iostream>
#include <unistd.h>

/*
 * GUI Widget Layout Engine
 * Integrates with Dear ImGui (MIT License - Omar Cornut)
 */

t_scan g_scan = {};
u_int8_t g_port_results[65536] = {0};

int init_gui_window();

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        std::cerr << ">>Error: You need root privileges (sudo) to run this program ." << std::endl;
        return 1;
    }

    std::cout << "[+] Launching pfe_ft_nmap Desktop GUI Engine..." << std::endl;

    int status = init_gui_window();
    
    return status;
}