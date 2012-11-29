/*
 * Copyright (c) 2012, Nasel
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdexcept>
#include <sstream>
#include <memory>
#include <cassert>
#include <cstring>
#include "utils.h"
#ifndef WIN32
    #ifdef BSD
        #include <sys/socket.h>
        #include <netinet/in.h>
        #include <net/if_dl.h>
    #else
        #include <netpacket/packet.h>
    #endif
    #include <netdb.h>
    #include <net/if.h>
#endif
#include "pdu.h"
#include "arp.h"
#include "ethernetII.h"
#include "endianness.h"
#include "network_interface.h"
#include "packet_sender.h"
#include "cxxstd.h"

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

namespace Tins {

bool Utils::Internals::from_hex(const string &str, uint32_t &result) {
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

void Utils::Internals::skip_line(istream &input) {
    int c = 0;
    while(c != '\n' && input)
         c = input.get();
}

/** \endcond */

IPv4Address Utils::resolve_ip(const string &to_resolve) {
    struct hostent *data = gethostbyname(to_resolve.c_str());
    if(!data)
        throw std::runtime_error("Could not resolve IP");
    return IPv4Address(((struct in_addr**)data->h_addr_list)[0]->s_addr);
}

bool Utils::resolve_hwaddr(const NetworkInterface &iface, IPv4Address ip, 
  HWAddress<6> *address, PacketSender &sender) 
{
    IPv4Address my_ip;
    NetworkInterface::Info info(iface.addresses());
    EthernetII packet = ARP::make_arp_request(iface, ip, info.ip_addr, info.hw_addr);
    #if TINS_IS_CXX11
        std::unique_ptr<PDU> response(sender.send_recv(packet));
    #else
        std::auto_ptr<PDU> response(sender.send_recv(packet));
    #endif
    if(response.get()) {
        ARP *arp_resp = response->find_pdu<ARP>();
        if(arp_resp)
            *address = arp_resp->sender_hw_addr();
        return arp_resp;
    }
    else
        return false;
}

HWAddress<6> Utils::resolve_hwaddr(const NetworkInterface &iface, IPv4Address ip, PacketSender &sender) 
{
    IPv4Address my_ip;
    NetworkInterface::Info info(iface.addresses());
    EthernetII packet = ARP::make_arp_request(iface, ip, info.ip_addr, info.hw_addr);
    std::auto_ptr<PDU> response(sender.send_recv(packet));
    if(response.get()) {
        const ARP *arp_resp = response->find_pdu<ARP>();
        if(arp_resp)
            return arp_resp->sender_hw_addr();
    }
    throw std::runtime_error("Could not resolve hardware address");
}

bool Utils::gateway_from_ip(IPv4Address ip, IPv4Address &gw_addr) {
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

set<string> Utils::network_interfaces() {
    InterfaceCollector collector;
    generic_iface_loop(collector);
    return collector.ifaces;
}

uint16_t Utils::channel_to_mhz(uint16_t channel) {
    return 2407 + (channel * 5);
}

uint16_t Utils::mhz_to_channel(uint16_t mhz) {
    return (mhz - 2407) / 5;
}

uint32_t Utils::do_checksum(const uint8_t *start, const uint8_t *end) {
    uint32_t checksum(0);
    uint16_t *ptr = (uint16_t*)start, *last = (uint16_t*)end, padding(0);
    if(((end - start) & 1) == 1) {
        last = (uint16_t*)end - 1;
        padding = *(end - 1) << 8;
    }
    while(ptr < last)
        checksum += Endian::host_to_be(*(ptr++));
    return checksum + padding;
}

uint32_t Utils::pseudoheader_checksum(IPv4Address source_ip, IPv4Address dest_ip, uint32_t len, uint32_t flag) {
    uint32_t checksum(0);
    uint32_t source_ip_int = Endian::host_to_be<uint32_t>(source_ip),
             dest_ip_int = Endian::host_to_be<uint32_t>(dest_ip);
    uint16_t *ptr = (uint16_t*)&source_ip_int;

    checksum += (uint32_t)(*ptr) + (uint32_t)(*(ptr+1));
    ptr = (uint16_t*)&dest_ip_int;
    checksum += (uint32_t)(*ptr) + (uint32_t)(*(ptr+1));
    checksum += flag + len;
    return checksum;
}

uint32_t Utils::pseudoheader_checksum(IPv6Address source_ip, IPv6Address dest_ip, uint32_t len, uint32_t flag) {
    uint32_t checksum = 0;
    IPv6Address::const_iterator it;
    for(it = source_ip.begin(); it != source_ip.end(); ++it)
        checksum += *it;
    for(it = dest_ip.begin(); it != dest_ip.end(); ++it)
        checksum += *it;
    checksum += flag + len;
    return checksum;
}

uint32_t Utils::crc32(const uint8_t* data, uint32_t data_size) {
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
}
