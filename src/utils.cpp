#include <stdexcept>
#include <sstream>
#include <cassert>
#ifndef WIN32
    #include <netdb.h>
#endif
#include "utils.h"

using namespace std;

uint32_t Tins::Utils::ip_to_int(const string &ip) {
    uint32_t result(0), i(0), end, bytes_found(0);
    while(i < ip.size() && bytes_found < 4) {
        uint8_t this_byte(0);
        end = i + 3;
        while(i < ip.size() && i < end && ip[i] != '.') {
            if(ip[i] < '0' || ip[i] > '9')
                throw std::runtime_error("Non-digit character found in ip");
            this_byte = (this_byte * 10)  + (ip[i] - '0');
            i++;
        }
        result = (result << 8) | this_byte;
        bytes_found++;
        if(bytes_found < 4 && i < ip.size() && ip[i] == '.')
            i++;
    }
    if(bytes_found < 4 || (i < ip.size() && bytes_found == 4))
        throw std::runtime_error("Invalid ip address");
    return net_to_host_l(result);
}

string Tins::Utils::ip_to_string(uint32_t ip) {
    ostringstream oss;
    int mask(24);
    ip = net_to_host_l(ip);
    while(mask >=0) {
        oss << ((ip >> mask) & 0xff);
        if(mask)
            oss << '.';
        mask -= 8;
    }
    return oss.str();
}

uint32_t Tins::Utils::resolve_ip(const string &to_resolve) {
    struct hostent *data = gethostbyname(to_resolve.c_str());
    if(!data)
        return 0;
    return ((struct in_addr**)data->h_addr_list)[0]->s_addr;
}
