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
