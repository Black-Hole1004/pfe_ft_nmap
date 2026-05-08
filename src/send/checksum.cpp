#include "functions.hpp"

unsigned short checksum(unsigned short *addr, size_t len)
{
    (void)addr;
    (void)len;
    return 0;
}

void calculate_checksum(u_int8_t protocol, t_packet_header *packet, unsigned short packet_size, t_IP *IP)
{
    (void)protocol;
    (void)packet;
    (void)packet_size;
    (void)IP;
}
