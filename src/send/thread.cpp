#include "functions.hpp"
#include <pthread.h>
#include <iostream>
#include <unistd.h>
#include <vector>

#define THREAD_COUNT 4

static std::vector<unsigned short> target_ports; 
static std::string target_ip_str;
static size_t current_port_index = 0;

pthread_mutex_t port_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

void *routine(void *arg)
{
    long thread = (long)arg;

    while(true) {
        int portScan = -1;
        pthread_mutex_lock(&port_mutex);

        if(current_port_index < target_ports.size()) {
            portScan = target_ports[current_port_index];
            current_port_index++;
        }

        pthread_mutex_unlock(&port_mutex);

        if(portScan == -1) 
            break;

        pthread_mutex_lock(&print_mutex);
        std::cout << "[Thread " << thread << "] Crafting packet for Port: " << portScan << std::endl;
        pthread_mutex_unlock(&print_mutex);
    
        struct sockaddr_in dest_info;
        dest_info.sin_family = AF_INET;
        dest_info.sin_port = htons(portScan);
        dest_info.sin_addr.s_addr = inet_addr("192.168.1.107"); 

        t_packet_header packet = create_packet(SYN);

        packet.ipv4.saddr = inet_addr("192.168.1.106");
        packet.ipv4.daddr = dest_info.sin_addr.s_addr;
        packet.tcp.source = htons(54321);
        packet.tcp.dest = htons(portScan);

        calculate_checksum(IPPROTO_TCP, &packet, sizeof(t_packet_header), NULL);

        sendto(raw_socket_fd, &packet, sizeof(t_packet_header), 0, 
            (struct sockaddr *)&dest_info, sizeof(dest_info));

    }
    
    pthread_mutex_lock(&print_mutex);
    std::cout << "[Thread " << thread << "] Finished work and exiting." << std::endl;
    pthread_mutex_unlock(&print_mutex);
    return nullptr;
}

void thread_send(const std::string& target_ip, const std::vector<unsigned short>& ports) {
    pthread_t threads[THREAD_COUNT];

    target_ports = ports;
    target_ip_str = target_ip;
    current_port_index = 0;

    std::cout << "Spawning " << THREAD_COUNT << " worker threads..." << std::endl;

    for (long i = 0; i < THREAD_COUNT; i++)
    {
        if (pthread_create(&threads[i], NULL, routine, (void *)i) != 0)
        {
            std::cout << ">>Error: Failed to create thread " << i << std::endl;
            return;
        }
    }

    for (int i = 0; i < THREAD_COUNT; i++)
    {
        pthread_join(threads[i], NULL);
    }

    std::cout << "All sender threads completed successfully!" << std::endl;
}