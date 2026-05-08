#include "functions.hpp"

t_packet_header create_packet(t_technique technique)
{
    (void)technique;
    return (t_packet_header){0};
}

int create_socket(int protocol)
{
    (void)protocol;
    return -1;
}
