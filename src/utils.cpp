/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdexcept>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <iostream> //borrame
#include <cassert>
#include <cstring>
#ifndef WIN32
    #include <netdb.h>
    #include <linux/if_packet.h>
    #include <net/if.h>
#endif
#include "utils.h"
#include "pdu.h"
#include "arp.h"


using namespace std;


/** \cond */
struct InterfaceCollector {
    set<string> ifaces;

    void operator() (struct ifaddrs *addr) {
        ifaces.insert(addr->ifa_name);
    }
};

struct IPv4Collector {
    uint32_t ip;
    bool found;
    const char *iface;

    IPv4Collector(const char *interface) : ip(0), found(false), iface(interface) { }

    void operator() (struct ifaddrs *addr) {
        if(!found && addr->ifa_addr->sa_family == AF_INET && !strcmp(addr->ifa_name, iface)) {
            ip = ((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr;
            found = true;
        }
    }
};

struct HWAddressCollector {
    uint8_t *result;
    bool found;
    const char *iface;

    HWAddressCollector(uint8_t *res, const char *interface) : result(res), found(false), iface(interface) { }

    void operator() (struct ifaddrs *addr) {
        if(!found && addr->ifa_addr->sa_family == AF_PACKET && !strcmp(addr->ifa_name, iface)) {
            memcpy(result, ((struct sockaddr_ll*)addr->ifa_addr)->sll_addr, 6);
            found = true;
        }
    }
};

bool from_hex(const string &str, uint32_t &result) {
    unsigned i(0);
    result = 0;
    while(i < str.size()) {
        uint8_t tmp;
        if(str[i] >= 'A' && str[i] <= 'F')
            tmp = (str[i] - 'A' + 10);
        else if(str[i] >= '0' && str[i] <= '9')
            tmp = (str[i] - '0');
        else
            return false;
        result = (result << 4) | tmp;
        i++;
    }
    return true;
}

void skip_line(istream &input) {
    int c = 0;
    while(c != '\n' && input)
         c = input.get();
}

/** \endcond */

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

bool Tins::Utils::hwaddr_to_byte(const std::string &hw_addr, uint8_t *array) {
    if(hw_addr.size() != 17)
        return false;
    unsigned i(0), arr_index(0);
    uint8_t tmp;
    while(i < hw_addr.size()) {
        unsigned end=i+2;
        tmp = 0;
        while(i < end) {
            if(hw_addr[i] >= 'a' && hw_addr[i] <= 'f')
                tmp = (tmp << 4) | (hw_addr[i] - 'a' + 10);
            else if(hw_addr[i] >= '0' && hw_addr[i] <= '9')
                tmp = (tmp << 4) | (hw_addr[i] - '0');
            else
                return false;
            i++;
        }
        array[arr_index++] = tmp;
        if(i < hw_addr.size()) {
            if(hw_addr[i] == ':')
                i++;
            else
                return false;
        }
    }
    return true;
}

string Tins::Utils::hwaddr_to_string(const uint8_t *array) {
    ostringstream oss;
    oss << hex;
    for(unsigned i(0); i < 6; ++i) {
        if(array[i] < 0x10)
            oss << '0';
        oss << (unsigned)array[i];
        if(i < 5)
            oss << ':';
    }
    return oss.str();
}

uint32_t Tins::Utils::resolve_ip(const string &to_resolve) {
    struct hostent *data = gethostbyname(to_resolve.c_str());
    if(!data)
        return 0;
    return ((struct in_addr**)data->h_addr_list)[0]->s_addr;
}

bool Tins::Utils::resolve_hwaddr(const string &iface, uint32_t ip, uint8_t *buffer, PacketSender *sender) {
    uint32_t my_ip;
    uint8_t my_hw[6];
    if(!interface_ip(iface, my_ip) || !interface_hwaddr(iface, my_hw))
        return false;
    PDU *packet = ARP::make_arp_request(iface, ip, my_ip, my_hw);
    PDU *response = sender->send_recv(packet);
    delete packet;
    if(response) {
        ARP *arp_resp = dynamic_cast<ARP*>(response->inner_pdu());
        if(arp_resp)
            memcpy(buffer, arp_resp->sender_hw_addr(), 6);
        delete response;
        return arp_resp;
    }
    else
        return false;
}

string Tins::Utils::interface_from_ip(uint32_t ip) {
    ifstream input("/proc/net/route");
    bool match(false);
    string iface;
    string destination, mask;
    uint32_t destination_int, mask_int;
    skip_line(input);
    while(!match) {
        input >> iface >> destination;
        for(unsigned i(0); i < 6; ++i)
            input >> mask;
        from_hex(destination, destination_int);
        from_hex(mask, mask_int);
        if((ip & mask_int) == destination_int)
            return iface;
        skip_line(input);
    }
    return "";
}

set<string> Tins::Utils::network_interfaces() {
    InterfaceCollector collector;
    generic_iface_loop(collector);
    return collector.ifaces;
}

bool Tins::Utils::interface_ip(const string &iface, uint32_t &ip) {
    IPv4Collector collector(iface.c_str());
    generic_iface_loop(collector);
    ip = collector.ip;
    return collector.found;
}

bool Tins::Utils::interface_hwaddr(const string &iface, uint8_t *buffer) {
    HWAddressCollector collector(buffer, iface.c_str());
    generic_iface_loop(collector);
    return collector.found;
}

bool Tins::Utils::interface_id(const string &iface, uint32_t &id) {
    id = if_nametoindex(iface.c_str());
    return (((int32_t)id) != -1);
}

uint16_t Tins::Utils::channel_to_mhz(uint16_t channel) {
    return 2407 + (channel * 5);
}

uint32_t Tins::Utils::crc32(uint8_t* data, uint32_t data_size) {
    uint32_t i, crc = 0;
    static uint32_t crc_table[] = {
        0x4DBDF21C, 0x500AE278, 0x76D3D2D4, 0x6B64C2B0,
        0x3B61B38C, 0x26D6A3E8, 0x000F9344, 0x1DB88320,
        0xA005713C, 0xBDB26158, 0x9B6B51F4, 0x86DC4190,
        0xD6D930AC, 0xCB6E20C8, 0xEDB71064, 0xF0000000
    };

    for (i = 0; i < data_size; ++i) {
        crc = (crc >> 4) ^ crc_table[(crc ^ data[i]) & 0x0F];
        crc = (crc >> 4) ^ crc_table[(crc ^ (data[i] >> 4)) & 0x0F];
    }

    return crc;
}
