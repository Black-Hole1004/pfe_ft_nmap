#include "functions.hpp"
#include <pthread.h>
#include <iostream>
#include <unistd.h>
#include <vector>
#include <cstring>

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
        std::memset(&dest_info, 0, sizeof(dest_info));
        dest_info.sin_family = AF_INET;
        dest_info.sin_port = htons(portScan);
        dest_info.sin_addr.s_addr = inet_addr(target_ip_str.c_str()); 
        
        char raw_packet_buffer[40];
        std::memset(raw_packet_buffer, 0, sizeof(raw_packet_buffer));
        
        t_tcp_ipv4_packet template_packet = create_packet(SYN);
        
        struct iphdr *ip_layer   = (struct iphdr *)(raw_packet_buffer);
        struct tcphdr *tcp_layer = (struct tcphdr *)(raw_packet_buffer + sizeof(struct iphdr));
        
        std::memcpy(ip_layer, &(template_packet.ipv4), sizeof(struct iphdr));
        std::memcpy(tcp_layer, &(template_packet.tcp), sizeof(struct tcphdr));
        
        ip_layer->id      = htons(12345);
        ip_layer->tot_len = htons(40);
        tcp_layer->seq    = htonl(11223344);

        unsigned short random_source_port = 49152 + (rand() % (65535 - 49152));

        if (target_ip_str == "127.0.0.1") {
            ip_layer->saddr = inet_addr("127.0.0.1");
        } else {
            ip_layer->saddr = inet_addr("172.28.240.139");
        }
        ip_layer->daddr = dest_info.sin_addr.s_addr;
        ip_layer->tot_len = htons(40);

        tcp_layer->source = htons(random_source_port);
        tcp_layer->dest = htons(portScan);

        calculate_checksum(IPPROTO_TCP, (t_tcp_ipv4_packet *)raw_packet_buffer, 40, NULL);

        pthread_mutex_lock(&print_mutex);
        std::cout << "\n--- RAW BUFFER DUMP FOR PORT " << portScan << " ---" << std::endl;
        for (int i = 0; i < 40; i++) {
            printf("%02X ", (unsigned char)raw_packet_buffer[i]);
            if ((i + 1) % 16 == 0) std::cout << std::endl;
        }
        std::cout << "\n----------------------------------------\n" << std::endl;
        pthread_mutex_unlock(&print_mutex);


        ssize_t bytes_sent = sendto(raw_socket_fd, raw_packet_buffer, 40, 0, 
                                    (struct sockaddr *)&dest_info, sizeof(dest_info));

        if (bytes_sent < 0) {
            pthread_mutex_lock(&print_mutex);
            std::cerr << ">> [Thread " << thread << "] sendto failed on port " 
                    << portScan << std::endl;
            pthread_mutex_unlock(&print_mutex);
        }
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