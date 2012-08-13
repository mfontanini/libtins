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
#include <stdexcept>
#include <cassert>
#include <cstring>
#ifndef WIN32
    #include <netdb.h>
    #include <linux/if_packet.h>
    #include <net/if.h>
#endif
#include "utils.h"
#include "pdu.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"


using namespace std;


/** \cond */
struct InterfaceCollector {
    set<string> ifaces;

    bool operator() (struct ifaddrs *addr) {
        ifaces.insert(addr->ifa_name);
        return true;
    }
};

struct IPv4Collector {
    uint32_t ip;
    bool found;
    const char *iface;

    IPv4Collector(const char *interface) : ip(0), found(false), iface(interface) { }

    bool operator() (struct ifaddrs *addr) {
        if(!found && addr->ifa_addr->sa_family == AF_INET && !strcmp(addr->ifa_name, iface)) {
            ip = ((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr;
            found = true;
        }
        return found;
    }
};

bool Tins::Utils::Internals::from_hex(const string &str, uint32_t &result) {
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

void Tins::Utils::Internals::skip_line(istream &input) {
    int c = 0;
    while(c != '\n' && input)
         c = input.get();
}

/** \endcond */

uint32_t Tins::Utils::ip_to_int(const string &ip) throw (std::runtime_error) {
    uint32_t result(0), i(0), end, bytes_found(0);
    while(i < ip.size() && bytes_found < 4) {
        uint16_t this_byte(0);
        end = i + 3;
        while(i < ip.size() && i < end && ip[i] != '.') {
            if(ip[i] < '0' || ip[i] > '9')
                throw std::runtime_error("Non-digit character found in ip");
            this_byte = (this_byte * 10)  + (ip[i] - '0');
            i++;
        }
        if (this_byte > 0xFF) {
            throw std::runtime_error("Byte greater than 255");
        }
        result = (result << 8) | (this_byte & 0xFF);
        bytes_found++;
        if(bytes_found < 4 && i < ip.size() && ip[i] == '.')
            i++;
    }
    if(bytes_found < 4 || (i < ip.size() && bytes_found == 4))
        throw std::runtime_error("Invalid ip address");
    return result;
}

string Tins::Utils::ip_to_string(uint32_t ip) {
    ostringstream oss;
    int mask(24);
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
        throw std::runtime_error("Could not resolve IP");
    return Utils::net_to_host_l(((struct in_addr**)data->h_addr_list)[0]->s_addr);
}

Tins::PDU *Tins::Utils::ping_address(IPv4Address ip, PacketSender *sender, IPv4Address ip_src) {
    ICMP *icmp = new ICMP(ICMP::ECHO_REQUEST);
    if(!ip_src) {
        try {
            NetworkInterface iface(ip);
            ip_src = iface.addresses().ip_addr;
        } catch(...) {
            return 0;
        }
    }
    IP ip_packet(ip, ip_src, icmp);
    return sender->send_recv(&ip_packet);
}

bool Tins::Utils::resolve_hwaddr(const NetworkInterface &iface, IPv4Address ip, 
  HWAddress<6> *address, PacketSender *sender) 
{
    IPv4Address my_ip;
    NetworkInterface::Info info(iface.addresses());
    PDU *packet = ARP::make_arp_request(iface, ip, info.ip_addr, info.hw_addr);
    PDU *response = sender->send_recv(packet);
    delete packet;
    if(response) {
        ARP *arp_resp = dynamic_cast<ARP*>(response->inner_pdu());
        if(arp_resp)
            *address = arp_resp->sender_hw_addr();
        delete response;
        return arp_resp;
    }
    else
        return false;
}

bool Tins::Utils::gateway_from_ip(IPv4Address ip, IPv4Address &gw_addr) {
    typedef std::vector<RouteEntry> entries_type;
    entries_type entries;
    uint32_t ip_int = ip;
    route_entries(std::back_inserter(entries));
    for(entries_type::const_iterator it(entries.begin()); it != entries.end(); ++it) {
        if((ip_int & it->mask) == it->destination) {
            gw_addr = it->gateway;
            return true;
        }
    }
    return false;
}

set<string> Tins::Utils::network_interfaces() {
    InterfaceCollector collector;
    generic_iface_loop(collector);
    return collector.ifaces;
}

uint16_t Tins::Utils::channel_to_mhz(uint16_t channel) {
    return 2407 + (channel * 5);
}

uint32_t Tins::Utils::do_checksum(const uint8_t *start, const uint8_t *end) {
    uint32_t checksum(0);
    uint16_t *ptr = (uint16_t*)start, *last = (uint16_t*)end, padding(0);
    if(((end - start) & 1) == 1) {
        last = (uint16_t*)end - 1;
        padding = *(end - 1) << 8;
    }
    while(ptr < last)
        checksum += Utils::net_to_host_s(*(ptr++));
    return checksum + padding;
}

uint32_t Tins::Utils::pseudoheader_checksum(uint32_t source_ip, uint32_t dest_ip, uint32_t len, uint32_t flag) {
    uint32_t checksum(0);
    uint16_t *ptr = (uint16_t*)&source_ip;

    checksum += (uint32_t)(*ptr) + (uint32_t)(*(ptr+1));
    ptr = (uint16_t*)&dest_ip;
    checksum += (uint32_t)(*ptr) + (uint32_t)(*(ptr+1));
    checksum += flag + len;
    return checksum;
}

uint32_t Tins::Utils::crc32(const uint8_t* data, uint32_t data_size) {
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
