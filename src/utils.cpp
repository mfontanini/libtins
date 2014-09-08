/*
 * Copyright (c) 2014, Matias Fontanini
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
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <sys/socket.h>
        #include <netinet/in.h>
        #include <net/if_dl.h>
    #else
        #include <netpacket/packet.h>
    #endif
    #include <netdb.h>
    #include <net/if.h>
#else
    #include <ws2tcpip.h>
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
    
    #ifdef WIN32
    bool operator() (PIP_ADAPTER_ADDRESSES addr) {
        ifaces.insert(addr->AdapterName);
        return false;
    }
    #else
    bool operator() (struct ifaddrs *addr) {
        ifaces.insert(addr->ifa_name);
        return false;
    }
    #endif
};

addrinfo *resolve_domain(const std::string &to_resolve, int family) {
    addrinfo *result, hints = addrinfo();
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_family = family;
    if(!getaddrinfo(to_resolve.c_str(), 0, &hints, &result)) 
        return result;
    else {
        throw std::runtime_error("Could not resolve address");
    }
}

namespace Tins {

/** \endcond */
namespace Utils {

IPv4Address resolve_domain(const std::string &to_resolve) {
    addrinfo *result = ::resolve_domain(to_resolve, AF_INET);
    IPv4Address addr(((sockaddr_in*)result->ai_addr)->sin_addr.s_addr);
    freeaddrinfo(result);
    return addr;
}

IPv6Address resolve_domain6(const std::string &to_resolve) {
    addrinfo *result = ::resolve_domain(to_resolve, AF_INET6);
    IPv6Address addr((const uint8_t*)&((sockaddr_in6*)result->ai_addr)->sin6_addr);
    freeaddrinfo(result);
    return addr;
}

HWAddress<6> resolve_hwaddr(const NetworkInterface &iface, IPv4Address ip, PacketSender &sender) 
{
    IPv4Address my_ip;
    NetworkInterface::Info info(iface.addresses());
    EthernetII packet = ARP::make_arp_request(ip, info.ip_addr, info.hw_addr);
    Internals::smart_ptr<PDU>::type response(sender.send_recv(packet, iface));
    if(response.get()) {
        const ARP *arp_resp = response->find_pdu<ARP>();
        if(arp_resp)
            return arp_resp->sender_hw_addr();
    }
    throw std::runtime_error("Could not resolve hardware address");
}

HWAddress<6> resolve_hwaddr(IPv4Address ip, PacketSender &sender) {
    return resolve_hwaddr(sender.default_interface(), ip, sender);
}

std::vector<RouteEntry> route_entries() {
    std::vector<RouteEntry> entries;
    route_entries(std::back_inserter(entries));
    return entries;
}

bool gateway_from_ip(IPv4Address ip, IPv4Address &gw_addr) {
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

set<string> network_interfaces() {
    InterfaceCollector collector;
    generic_iface_loop(collector);
    return collector.ifaces;
}

uint16_t channel_to_mhz(uint16_t channel) {
    return 2407 + (channel * 5);
}

uint16_t mhz_to_channel(uint16_t mhz) {
    return (mhz - 2407) / 5;
}
    
std::string to_string(PDU::PDUType pduType) {
#define ENUM_TEXT(p) case(PDU::p): return #p;
    switch(pduType){
        ENUM_TEXT(RAW);
        ENUM_TEXT(ETHERNET_II);
        ENUM_TEXT(IEEE802_3);
        ENUM_TEXT(RADIOTAP);
        ENUM_TEXT(DOT11);
        ENUM_TEXT(DOT11_ACK);
        ENUM_TEXT(DOT11_ASSOC_REQ);
        ENUM_TEXT(DOT11_ASSOC_RESP);
        ENUM_TEXT(DOT11_AUTH);
        ENUM_TEXT(DOT11_BEACON);
        ENUM_TEXT(DOT11_BLOCK_ACK);
        ENUM_TEXT(DOT11_BLOCK_ACK_REQ);
        ENUM_TEXT(DOT11_CF_END);
        ENUM_TEXT(DOT11_DATA);
        ENUM_TEXT(DOT11_CONTROL);
        ENUM_TEXT(DOT11_DEAUTH);
        ENUM_TEXT(DOT11_DIASSOC);
        ENUM_TEXT(DOT11_END_CF_ACK);
        ENUM_TEXT(DOT11_MANAGEMENT);
        ENUM_TEXT(DOT11_PROBE_REQ);
        ENUM_TEXT(DOT11_PROBE_RESP);
        ENUM_TEXT(DOT11_PS_POLL);
        ENUM_TEXT(DOT11_REASSOC_REQ);
        ENUM_TEXT(DOT11_REASSOC_RESP);
        ENUM_TEXT(DOT11_RTS);
        ENUM_TEXT(DOT11_QOS_DATA);
        ENUM_TEXT(LLC);
        ENUM_TEXT(SNAP);
        ENUM_TEXT(IP);
        ENUM_TEXT(ARP);
        ENUM_TEXT(TCP);
        ENUM_TEXT(UDP);
        ENUM_TEXT(ICMP);
        ENUM_TEXT(BOOTP);
        ENUM_TEXT(DHCP);
        ENUM_TEXT(EAPOL);
        ENUM_TEXT(RC4EAPOL);
        ENUM_TEXT(RSNEAPOL);
        ENUM_TEXT(DNS);
        ENUM_TEXT(LOOPBACK);
        ENUM_TEXT(IPv6);
        ENUM_TEXT(ICMPv6);
        ENUM_TEXT(SLL);
        ENUM_TEXT(DHCPv6);
        ENUM_TEXT(DOT1Q);
        ENUM_TEXT(PPPOE);
        ENUM_TEXT(STP);
        ENUM_TEXT(PPI);
        ENUM_TEXT(IPSEC_AH);
        ENUM_TEXT(IPSEC_ESP);
        ENUM_TEXT(USER_DEFINED_PDU);
        default: return "";
    }
#undef ENUM_TEXT
}

uint32_t do_checksum(const uint8_t *start, const uint8_t *end) {
    uint32_t checksum(0);
    const uint8_t *last = end;
    uint16_t buffer = 0;
    uint16_t padding = 0;
    const uint8_t *ptr = start;

    if(((end - start) & 1) == 1) {
        last = end - 1;
        padding = *(end - 1) << 8;
    }

    while(ptr < last) {
        memcpy(&buffer, ptr, sizeof(uint16_t));
        checksum += Endian::host_to_be(buffer);
        ptr += sizeof(uint16_t);
    }

    return checksum + padding;
}

uint32_t pseudoheader_checksum(IPv4Address source_ip, IPv4Address dest_ip, uint32_t len, uint32_t flag) {
    uint32_t checksum(0);
    uint32_t source_ip_int = Endian::host_to_be<uint32_t>(source_ip),
             dest_ip_int = Endian::host_to_be<uint32_t>(dest_ip);
    char buffer[sizeof(uint32_t) * 2];
    uint16_t *ptr = (uint16_t*)buffer, *end = (uint16_t*)(buffer + sizeof(buffer));
    std::memcpy(buffer, &source_ip_int, sizeof(source_ip_int));
    std::memcpy(buffer + sizeof(uint32_t), &dest_ip_int, sizeof(dest_ip_int));
    while(ptr < end) 
        checksum += (uint32_t)*ptr++;
    checksum += flag + len;
    return checksum;
}

uint32_t pseudoheader_checksum(IPv6Address source_ip, IPv6Address dest_ip, uint32_t len, uint32_t flag) {
    uint32_t checksum(0);
    uint16_t *ptr = (uint16_t*) source_ip.begin();
    uint16_t *end = (uint16_t*) source_ip.end();
    while(ptr < end)
        checksum += (uint32_t) Endian::be_to_host(*ptr++);

    ptr = (uint16_t*) dest_ip.begin();
    end = (uint16_t*) dest_ip.end();
    while(ptr < end)
        checksum += (uint32_t) Endian::be_to_host(*ptr++);
    checksum += flag + len;
    return checksum;
}

uint32_t crc32(const uint8_t* data, uint32_t data_size) {
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
}
