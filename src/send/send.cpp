#include "functions.hpp"
#include <iostream>
#include <cstring>

void init_send()
{
    std::cout << "Sending packets..." << std::endl;
    if (g_scan.options.thread_count > 1)
        thread_send();
    else {
        for (int technique = 0; technique < TECHNIQUE_COUNT; technique++)
            if (g_scan.options.technique[technique])
            {
                t_options *options = new t_options();
                std::memset(options, 0, sizeof(t_options));
                std::memcpy(options, &g_scan.options, sizeof(t_options));
                for (int i = 0; i < TECHNIQUE_COUNT; i++)
                    options->technique[i] = false;
                options->technique[technique] = true;
                routine(options);
            }
    }
}
