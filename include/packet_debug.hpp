// TEMPORARY DEBUG FILE - TO BE REMOVED AFTER DEBUGGING
// This file contains packet printing functions for debugging purposes

#ifndef PACKET_DEBUG_HPP
#define PACKET_DEBUG_HPP

#include "types.hpp"
#include <string>
#include <pcap/pcap.h>

// Print hex dump of raw data
void print_hex_dump(const unsigned char *data, size_t len, const std::string& prefix = "");

// Print TCP flags in human-readable format
void print_tcp_flags(const struct tcphdr *tcp);

// Print outgoing packet details (after creation, before sending)
void print_outgoing_packet(const t_packet_header *packet, int protocol,
                           const char *dest_ip, int dest_port, const char *technique_name);

// Print incoming packet details (after receiving)
void print_incoming_packet(const unsigned char *data, size_t packet_len, int link_type);

#endif // PACKET_DEBUG_HPP
