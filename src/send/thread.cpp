<<<<<<< HEAD
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
=======
#include "functions.hpp"
#include <pthread.h>
#include <iostream>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <errno.h>
#include <iomanip>

static void dispatch(int amount, int *chunks, t_range chunk_range, bool *check)
{
    std::memset(chunks, 0, sizeof(int) * (chunk_range.max - chunk_range.min));
    int current = chunk_range.min;
    for (int i = 0; i < amount; i++)
    {
        if (current >= chunk_range.max)
            current = chunk_range.min;
        current++;
        if (check != NULL && !check[current - 1])
            i--;
        else
            chunks[current - 1]++;
    }
}

void *routine(void *arg)
{
    t_options *options = static_cast<t_options*>(arg);
    int technique;
    for (technique = 0; technique < TECHNIQUE_COUNT; technique++)
        if (options->technique[technique])
            break;

    t_packet_header packet = create_packet(static_cast<t_technique>(technique));
    unsigned short packet_size;
    int protocol;

    if (technique == UDP)
    {
        protocol = IPPROTO_UDP;
        packet_size = sizeof(struct udphdr);
    }
    else
    {
        protocol = IPPROTO_TCP;
        packet_size = sizeof(struct tcphdr);
    }

    int sock = create_socket(protocol);
    if (sock < 0) {
        delete options;
        return nullptr;
    }

    for (t_IP *IP = g_scan.ip; IP != NULL; IP = IP->next)
    {
        if (IP->is_down)
            continue;

        for (int port = 0; port <= USHRT_MAX; port++)
            if (options->port[port])
            {
                IP->status[technique][port] = FILTERED;
                if (technique == FIN || technique == NUL || technique == XMAS || technique == UDP)
                    IP->status[technique][port] = static_cast<t_status>(IP->status[technique][port] | OPEN);

                if (protocol == IPPROTO_TCP)
                {
                    packet.tcp.dest = htons(port);
                    packet.tcp.check = 0;
                }
                else
                {
                    packet.udp.dest = htons(port);
                    packet.udp.check = 0;
                }
                calculate_checksum(protocol, &packet, packet_size, IP);

                if (sendto(sock, &packet, packet_size, 0, &IP->addr.base, IP->addrlen) == -1)
                    std::cerr << "sendto: " << strerror(errno) << std::endl;
                usleep(1000);
            }
    }

    close(sock);
    delete options;
    return nullptr;
}

void thread_send()
{
    pthread_t threads[g_scan.options.thread_count];
    int id = 0;

    int chunks[TECHNIQUE_COUNT];
    dispatch(g_scan.options.thread_count, chunks, (t_range){0, TECHNIQUE_COUNT}, g_scan.options.technique);

    for (int technique = 0; technique < TECHNIQUE_COUNT; technique++)
        if (g_scan.options.technique[technique])
        {
            int threads_for_tech[chunks[technique]];
            dispatch(g_scan.options.port_count, threads_for_tech, (t_range){0, chunks[technique]}, NULL);

            int current = 0;
            for (int thread_no = 0; thread_no < chunks[technique]; thread_no++) {
                t_options *range = new t_options();
                std::memset(range, 0, sizeof(t_options));
                int amount = threads_for_tech[thread_no];

                for (int i = 0; i < TECHNIQUE_COUNT; i++)
                    range->technique[i] = false;
                range->technique[technique] = true;

                for (int i = 0; i <= USHRT_MAX; i++)
                    range->port[i] = false;

                for (; current <= USHRT_MAX && amount != 0; current++)
                    if (g_scan.options.port[current])
                    {
                        range->port[current] = true;
                        amount--;
                    }

                if (g_scan.options.verbose == 1)
                    std::cout << "\rSending " << get_technique_name(static_cast<t_technique>(technique)) << " packets...\t(" << (thread_no + 1) << "/" << chunks[technique] << ")" << std::flush;
                else if (g_scan.options.verbose == 2)
                    std::cout << "(thread id: " << id << " | technique: " << get_technique_name(static_cast<t_technique>(technique)) << " | amount of ports: " << threads_for_tech[thread_no] << ")" << std::endl;

                if (pthread_create(&threads[id++], NULL, routine, range) != 0)
                    std::cerr << "pthread_create: " << strerror(errno) << std::endl;
            }
        }

    for (int i = 0; i < id; i++)
        pthread_join(threads[i], NULL);

    if (g_scan.options.verbose == 1)
        std::cout << "\r" << std::left << std::setw(64) << "Every packets have been sent." << std::endl;
}
>>>>>>> b39337a23c080e112aeba490d67b505bb7b6703f
