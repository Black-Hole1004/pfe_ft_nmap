#include "Utils.hpp"
#include "functions.hpp"
#include <regex>
#include <sstream>
#include <iostream>
#include <cstdarg>
#include <cstdlib>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <cstring>
#include <vector>

Utils::Utils() {}

void Utils::noop() {}

void error(int code, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    free_IPs();
    exit(code);
}

char *get_technique_name(t_technique technique)
{
    switch (technique)
    {
    case ACK:  return (char*)"ACK";
    case SYN:  return (char*)"SYN";
    case FIN:  return (char*)"FIN";
    case NUL:  return (char*)"NULL";
    case XMAS: return (char*)"XMAS";
    case UDP:  return (char*)"UDP";
    default:   return (char*)"UNKNOWN";
    }
}

void print_status_name(t_status status)
{
    if (status == UNSCANNED)
        std::cout << "UNSCANNED ";
    if (status & OPEN)
        std::cout << "OPEN ";
    if (status & CLOSED)
        std::cout << "CLOSED ";
    if (status & FILTERED)
        std::cout << "FILTERED ";
    if (status & UNFILTERED)
        std::cout << "UNFILTERED ";
    std::cout << std::endl;
}

void add_IP(t_IP addr)
{
    t_IP *head = g_scan.ip;
    t_IP *new_node = nullptr;

    for (; head; head = head->next)
    {
        if (g_scan.ip_count > MAX_IPS)
            error(2, "add_IP: too many IPs (max: %d)\n", MAX_IPS);
        if ((g_scan.options.family == AF_INET && std::memcmp(&head->addr.ipv4.sin_addr, &addr.addr.ipv4.sin_addr, sizeof(struct in_addr)) == 0)
            || (g_scan.options.family == AF_INET6 && std::memcmp(&head->addr.ipv6.sin6_addr, &addr.addr.ipv6.sin6_addr, sizeof(struct in6_addr)) == 0))
        {
            fprintf(stderr, "Warning: %s: duplicate IP, ignoring\n", addr.name);
            return;
        }
        if (!head->next)
            break;
    }

    new_node = new t_IP();
    std::memset(new_node, 0, sizeof(t_IP));
    std::memcpy(new_node, &addr, sizeof(t_IP));
    new_node->next = nullptr;

    if (head == nullptr)
        g_scan.ip = new_node;
    else
        head->next = new_node;
    g_scan.ip_count++;
}

void free_IPs()
{
    t_IP *head = g_scan.ip;
    while (head)
    {
        t_IP *tmp = head;
        head = head->next;
        delete tmp;
    }
    g_scan.ip = nullptr;
}

int is_number(char *str)
{
    if (!str || !*str) return 0;
    for (unsigned char i = 0; str[i]; i++)
        if (str[i] < '0' || str[i] > '9')
            return 0;
    return 1;
}

void check_down()
{
    bool all_down = true;
    for (t_IP *IP = g_scan.ip; IP != NULL; IP = IP->next)
        if (!IP->is_down)
        {
            all_down = false;
            break;
        }
    if (all_down)
        error(1, "None of the hosts specified are up. Stopping now.\n");
}

int get_number(char *str)
{
    if (!str || !*str)
        error(2, "get_number: empty string\n");
    else if (!is_number(str))
        error(2, "get_number: %s: not a number\n", str);
    return std::atoi(str);
}

bool isValidIP(const std::string &ip)
{
    std::stringstream ss(ip);
    std::string segment;
    std::vector<int> segments;

    while (std::getline(ss, segment, '.')) {
        if (segment.empty() || segment.find_first_not_of("0123456789") != std::string::npos)
            return false;
        int value = std::stoi(segment);
        if (value < 0 || value > 255)
            return false;
        segments.push_back(value);
    }
    return segments.size() == 4;
}

std::string sanitizeIP(const std::string &IP)
{
    std::stringstream ss(IP);
    std::string octet;
    std::string cleanIP;
    int count = 0;

    while (std::getline(ss, octet, '.')) {
        size_t first_non_zero = octet.find_first_not_of('0');
        if (first_non_zero == std::string::npos)
            octet = "0";
        else
            octet = octet.substr(first_non_zero);
        if (count > 0)
            cleanIP += ".";
        cleanIP += octet;
        count++;
    }
    return cleanIP;
}

bool isValidCIDR(const std::string &cidr)
{
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos)
        return false;

    std::string ip_part = cidr.substr(0, slash_pos);
    std::string prefix_part = cidr.substr(slash_pos + 1);

    if (!isValidIP(ip_part))
        return false;

    if (prefix_part.empty() || prefix_part.find_first_not_of("0123456789") != std::string::npos)
        return false;

    int prefix_len = std::stoi(prefix_part);
    if (prefix_len < 0 || prefix_len > 32)
        return false;

    return true;
}

std::vector<std::string> expandCIDR(const std::string &cidr)
{
    std::vector<std::string> ips;

    size_t slash_pos = cidr.find('/');
    std::string ip_part = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));

    // Parse the base IP into 4 octets
    std::stringstream ss(ip_part);
    std::string segment;
    std::vector<int> octets;
    while (std::getline(ss, segment, '.')) {
        octets.push_back(std::stoi(segment));
    }

    // Calculate network address and number of hosts
    uint32_t base_ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    uint32_t mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF;
    uint32_t network = base_ip & mask;
    uint32_t num_hosts = (1U << (32 - prefix_len));

    // Limit expansion to reasonable size
    if (num_hosts > 65536) {
        std::cerr << ">>Warning: CIDR range too large (max 65536 hosts). Limiting to /16." << std::endl;
        num_hosts = 65536;
    }

    // Generate all IPs in the range (including network and broadcast addresses)
    // Modern networks and cloud environments often use all addresses
    for (uint32_t i = 0; i < num_hosts; i++) {
        uint32_t ip = network + i;

        char ip_str[16];
        std::snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                     (ip >> 24) & 0xFF,
                     (ip >> 16) & 0xFF,
                     (ip >> 8) & 0xFF,
                     ip & 0xFF);
        ips.push_back(std::string(ip_str));
    }

    return ips;
}

std::vector<unsigned short> split(const std::string &str, char del)
{
    std::vector<unsigned short> result;
    std::stringstream ss(str);
    std::string item;

    while (std::getline(ss, item, del)) {
        if (is_number((char*)item.c_str())) {
            unsigned int parsedValue = std::stoi(item);
            if (parsedValue >= 65535) {
                std::cout << ">>Error: Port " << parsedValue << " out of bounds (0-65535)." << std::endl;
                exit(1);
            }
            result.push_back(static_cast<unsigned short>(parsedValue));
        } else {
            std::cout << "error: " << item << " not a number." << std::endl;
            exit(1);
        }
    }
    return result;
}

t_sockaddr get_interface()
{
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1)
        error(1, "getifaddrs failed\n");

    t_sockaddr addr = {};
    struct ifaddrs *tmp = nullptr;

    // Check if any target is localhost — if so, prefer loopback interface
    bool localhost_target = false;
    for (t_IP *ip = g_scan.ip; ip; ip = ip->next)
    {
        if (g_scan.options.family == AF_INET && ip->addr.ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
            localhost_target = true;
        else if (g_scan.options.family == AF_INET6)
        {
            struct in6_addr loopback6 = IN6ADDR_LOOPBACK_INIT;
            if (!std::memcmp(&ip->addr.ipv6.sin6_addr, &loopback6, sizeof(struct in6_addr)))
                localhost_target = true;
        }
    }

    if (localhost_target)
    {
        for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
            if ((tmp->ifa_flags & IFF_LOOPBACK) && tmp->ifa_addr && tmp->ifa_addr->sa_family == g_scan.options.family)
            {
                std::memcpy(&addr, tmp->ifa_addr, sizeof(t_sockaddr));
                break;
            }
    }

    // Fall back to broadcast interface (typical external interface)
    if (tmp == NULL)
        for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
            if ((tmp->ifa_flags & IFF_BROADCAST) && tmp->ifa_addr && tmp->ifa_addr->sa_family == g_scan.options.family)
            {
                std::memcpy(&addr, tmp->ifa_addr, sizeof(t_sockaddr));
                break;
            }

    // Last resort: any interface with the right family
    if (tmp == NULL)
        for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next)
            if (tmp->ifa_addr && tmp->ifa_addr->sa_family == g_scan.options.family)
            {
                std::memcpy(&addr, tmp->ifa_addr, sizeof(t_sockaddr));
                break;
            }

    if (tmp == NULL)
        error(1, "get_interface: no interface found\n");
    else {
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(g_scan.options.family,
                  g_scan.options.family == AF_INET ? (void*)&addr.ipv4.sin_addr : (void*)&addr.ipv6.sin6_addr,
                  ip, sizeof(ip));
        if (g_scan.options.verbose)
            std::cout << "Interface: " << tmp->ifa_name << "(" << ip << ")" << std::endl;
    }

    freeifaddrs(ifaddr);
    return addr;
}

t_IP resolve_target(const std::string& host)
{
    struct addrinfo *res;
    struct addrinfo hints = {};
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = g_scan.options.family;

    int ret = getaddrinfo(host.c_str(), NULL, &hints, &res);
    if (ret != 0)
        error(1, "getaddrinfo: %s\n", gai_strerror(ret));

    t_IP ip = {};
    ip.addrlen = res->ai_addrlen;
    std::memcpy(&ip.addr, res->ai_addr, res->ai_addrlen);

    char ip_str[INET6_ADDRSTRLEN] = {};
    inet_ntop(res->ai_family,
              g_scan.options.family == AF_INET ? (void*)&ip.addr.ipv4.sin_addr : (void*)&ip.addr.ipv6.sin6_addr,
              ip_str, sizeof(ip_str));

    if (res->ai_canonname && std::strcmp(res->ai_canonname, ip_str) != 0)
        std::snprintf(ip.name, sizeof(ip.name), "%s(%s)", res->ai_canonname, ip_str);
    else
        std::snprintf(ip.name, sizeof(ip.name), "%s", ip_str);

    freeaddrinfo(res);
    return ip;
}

std::string find_pcap_device(const std::string& target_ip)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "pcap_findalldevs: " << errbuf << std::endl;
        return "";
    }

    std::string preferred = (target_ip == "127.0.0.1" || target_ip == "localhost") ? "lo" : "eth0";
    std::string device;

    for (pcap_if_t *d = alldevs; d; d = d->next) {
        if (preferred == d->name) {
            device = d->name;
            break;
        }
    }
    if (device.empty()) {
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            if (std::string(d->name) == "lo" || std::string(d->name) == "eth0" || std::string(d->name) == "any") {
                device = d->name;
                break;
            }
        }
    }
    if (device.empty() && alldevs) {
        device = alldevs->name;
    }

    pcap_freealldevs(alldevs);
    return device;
}
