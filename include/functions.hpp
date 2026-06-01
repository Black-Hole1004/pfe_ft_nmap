#ifndef FUNCTIONS_HPP
#define FUNCTIONS_HPP

#include "types.hpp"
#include "Parser.hpp"

// parser.cpp
void flag_parser(unsigned short *index, int argc , char *argv[], Parser &p);

// receive/pcap_handler.cpp
void packet_handler(unsigned char *user, const struct pcap_pkthdr *hdr, const unsigned char *data);

// send/send.cpp
extern int raw_socket_fd;
void init_send();

// send/thread.cpp
void *routine(void *arg);
void thread_send(const std::string& target_ip, const std::vector<unsigned short>& ports);

// send/network.cpp
t_tcp_ipv4_packet create_packet(t_technique technique);
int create_socket(int protocol);

// send/checksum.cpp
unsigned short checksum(unsigned short *addr, size_t len);
void calculate_checksum(u_int8_t protocol, t_tcp_ipv4_packet *packet, unsigned short packet_size, t_IP *IP);

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
