#include "Utils.hpp"

Utils::Utils()
{
}

void Utils::noop()
{
}
#include "functions.hpp"

void error(int code, char *fmt, ...)
{
    (void)code;
    (void)fmt;
}

char *get_technique_name(t_technique technique)
{
    (void)technique;
    return (char *)"UNKNOWN";
}

void print_status_name(t_status status)
{
    (void)status;
}

void add_IP(t_IP addr)
{
    (void)addr;
}

void free_IPs()
{
}

int is_number(char *str)
{
    (void)str;
    return 0;
}

void check_down()
{
}

int get_number(char *str)
{
    (void)str;
    return -1;
}
