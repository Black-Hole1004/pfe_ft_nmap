#ifndef FUNCTIONS_HPP
#define FUNCTIONS_HPP

#include "types.hpp"
#include "Parser.hpp"

// parser.cpp
void flag_parser(unsigned short *index, char *argv[], Parser &p);

// receive/pcap_handler.cpp
void packet_handler(unsigned char *user, const struct pcap_pkthdr *hdr, const unsigned char *data);

// send/send.cpp
void init_send();

// send/thread.cpp
void *routine(void *arg);
void thread_send();

// send/network.cpp
t_packet_header create_packet(t_technique technique);
int create_socket(int protocol);

// send/checksum.cpp
unsigned short checksum(unsigned short *addr, size_t len);
void calculate_checksum(u_int8_t protocol, t_packet_header *packet, unsigned short packet_size, t_IP *IP);

// utils/utils.cpp
void error(int code, char *fmt, ...);
char *get_technique_name(t_technique technique);
void print_status_name(t_status status);
void add_IP(t_IP addr);
void free_IPs();
int is_number(char *str);
void check_down();
int get_number(char *str);

#endif
