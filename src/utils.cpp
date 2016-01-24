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
#include <cstring>
#include <fstream>
#include "macros.h"
#ifndef _WIN32
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <sys/socket.h>
        #include <sys/file.h>
        #include <sys/sysctl.h>
        #include <net/route.h>
        #include <net/if_dl.h>
        #include <net/if.h>
        #include <netinet/in.h>
    #else
        #include <netpacket/packet.h>
    #endif
    #include <ifaddrs.h>
    #include <netdb.h>
    #include <net/if.h>
    #ifdef __ANDROID_API__
        #include <linux/in.h>
        #include <linux/in6.h>
    #endif
#else
    #include <winsock2.h>
    #include <iphlpapi.h>
    #include <ws2tcpip.h>
    #undef interface
#endif
#include "utils.h"
#include "pdu.h"
#include "arp.h"
#include "ethernetII.h"
#include "endianness.h"
#include "network_interface.h"
#include "packet_sender.h"
#include "cxxstd.h"
#include "hw_address.h"
#include "memory_helpers.h"

using std::string;
using std::set;
using std::ifstream;
using std::vector;
using std::back_inserter;
using std::runtime_error;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

/** \cond */
struct InterfaceCollector {
    set<string> ifaces;
    
    #ifdef _WIN32
    bool operator() (PIP_ADAPTER_ADDRESSES addr) {
        ifaces.insert(addr->AdapterName);
        return false;
    }
    #else
    bool operator() (struct ifaddrs* addr) {
        ifaces.insert(addr->ifa_name);
        return false;
    }
    #endif
};

addrinfo* resolve_domain(const string& to_resolve, int family) {
    addrinfo* result, hints = addrinfo();
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_family = family;
    if (!getaddrinfo(to_resolve.c_str(), 0, &hints, &result)) {
        return result;
    }
    else {
        throw runtime_error("Could not resolve address");
    }
}

#if defined(BSD) || defined(__FreeBSD_kernel__)
vector<char> query_route_table() {
    int mib[6];
    vector<char> buf;
    size_t len;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET;
    mib[4] = NET_RT_DUMP;
    mib[5] = 0; 
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        throw runtime_error("sysctl failed");
    }

    buf.resize(len);
    if (sysctl(mib, 6, &buf[0], &len, NULL, 0) < 0) {
        throw runtime_error("sysctl failed");
    }

    return buf;
}

template<typename ForwardIterator>
void parse_header(struct rt_msghdr* rtm, ForwardIterator iter) {
    char* ptr = (char *)(rtm + 1);
    sockaddr* sa = 0;

    for (int i = 0; i < RTAX_MAX; i++) {
        if (rtm->rtm_addrs & (1 << i)) {
            sa = (struct sockaddr *)ptr;
            ptr += sa->sa_len;
            if (sa->sa_family == 0) {
                sa = 0;
            }
        } 
        *iter++ = sa;
    }
}
#endif

namespace Tins {

/** \endcond */
namespace Utils {

IPv4Address resolve_domain(const string& to_resolve) {
    addrinfo* result = ::resolve_domain(to_resolve, AF_INET);
    IPv4Address addr(((sockaddr_in*)result->ai_addr)->sin_addr.s_addr);
    freeaddrinfo(result);
    return addr;
}

IPv6Address resolve_domain6(const string& to_resolve) {
    addrinfo* result = ::resolve_domain(to_resolve, AF_INET6);
    IPv6Address addr((const uint8_t*)&((sockaddr_in6*)result->ai_addr)->sin6_addr);
    freeaddrinfo(result);
    return addr;
}

HWAddress<6> resolve_hwaddr(const NetworkInterface& iface,
                            IPv4Address ip,
                            PacketSender& sender) {
    IPv4Address my_ip;
    NetworkInterface::Info info(iface.addresses());
    EthernetII packet = ARP::make_arp_request(ip, info.ip_addr, info.hw_addr);
    Internals::smart_ptr<PDU>::type response(sender.send_recv(packet, iface));
    if (response.get()) {
        const ARP* arp_resp = response->find_pdu<ARP>();
        if (arp_resp) {
            return arp_resp->sender_hw_addr();
        }
    }
    throw runtime_error("Could not resolve hardware address");
}

HWAddress<6> resolve_hwaddr(IPv4Address ip, PacketSender& sender) {
    return resolve_hwaddr(sender.default_interface(), ip, sender);
}

#if defined(BSD) || defined(__FreeBSD_kernel__)
vector<RouteEntry> route_entries() {
    vector<RouteEntry> output;
    vector<char> buffer = query_route_table();
    char* next = &buffer[0], *end = &buffer[buffer.size()];
    rt_msghdr* rtm;
    vector<sockaddr*> sa(RTAX_MAX);
    char iface_name[IF_NAMESIZE];
    while (next < end) {
        rtm = (rt_msghdr*)next;
        parse_header(rtm, sa.begin());
        if (sa[RTAX_DST] && sa[RTAX_GATEWAY] && if_indextoname(rtm->rtm_index, iface_name)) {
            RouteEntry entry;
            entry.destination = IPv4Address(((struct sockaddr_in *)sa[RTAX_DST])->sin_addr.s_addr);
            entry.gateway = IPv4Address(((struct sockaddr_in *)sa[RTAX_GATEWAY])->sin_addr.s_addr);
            if (sa[RTAX_GENMASK]) {
                entry.mask = IPv4Address(((struct sockaddr_in *)sa[RTAX_GENMASK])->sin_addr.s_addr);
            }
            else {
                entry.mask = IPv4Address(uint32_t());
            }
            entry.interface = iface_name;
            entry.metric = 0;
            output.push_back(entry);
        }
        next += rtm->rtm_msglen;
    }
    return output;
}
#elif defined(_WIN32)
vector<RouteEntry> route_entries() {
    vector<RouteEntry> output;
    MIB_IPFORWARDTABLE* table;
    ULONG size = 0;
    GetIpForwardTable(0, &size, 0);
    vector<uint8_t> buffer(size);
    table = (MIB_IPFORWARDTABLE*)&buffer[0];
    GetIpForwardTable(table, &size, 0);
    
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_IPFORWARDROW* row = &table->table[i];
        if (row->dwForwardType == MIB_IPROUTE_TYPE_INDIRECT || 
            row->dwForwardType == MIB_IPROUTE_TYPE_DIRECT) {
            RouteEntry entry;
            entry.interface = NetworkInterface::from_index(row->dwForwardIfIndex).name();
            entry.destination = IPv4Address(row->dwForwardDest);
            entry.mask = IPv4Address(row->dwForwardMask);
            entry.gateway = IPv4Address(row->dwForwardNextHop);
            entry.metric = row->dwForwardMetric1;
            output.push_back(entry);
        }
    }
    return output;
}
#else
vector<RouteEntry> route_entries() {
    using namespace Tins::Internals;
    vector<RouteEntry> output;
    ifstream input("/proc/net/route");
    string destination, mask, metric, gw;
    uint32_t dummy;
    skip_line(input);
    RouteEntry entry;
    while (input >> entry.interface >> destination >> gw) {
        for (unsigned i(0); i < 4; ++i) {
            input >> metric;
        }
        input >> mask;
        from_hex(destination, dummy);
        entry.destination = IPv4Address(dummy);
        from_hex(mask, dummy);
        entry.mask = IPv4Address(dummy);
        from_hex(gw, dummy);
        entry.gateway = IPv4Address(dummy);
        from_hex(metric, dummy);
        entry.metric = dummy;
        skip_line(input);
        output.push_back(entry);
    }
    return output;
}
#endif

bool gateway_from_ip(IPv4Address ip, IPv4Address& gw_addr) {
    typedef vector<RouteEntry> entries_type;
    entries_type entries;
    uint32_t ip_int = ip;
    route_entries(back_inserter(entries));
    for (entries_type::const_iterator it(entries.begin()); it != entries.end(); ++it) {
        if ((ip_int & it->mask) == it->destination) {
            gw_addr = it->gateway;
            return true;
        }
    }
    return false;
}

#ifdef _WIN32
set<string> network_interfaces() {
    set<string> output;
    ULONG size;
    ::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
    std::vector<uint8_t> buffer(size);
    if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
        PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
        while (iface) {
            output.insert(iface->AdapterName);
            iface = iface->Next;
        }
    }
    return output;
}
#else
set<string> network_interfaces() {
    set<string> output;
    struct ifaddrs* ifaddrs = 0;
    struct ifaddrs* if_it = 0;
    getifaddrs(&ifaddrs);
    for (if_it = ifaddrs; if_it; if_it = if_it->ifa_next) {
        output.insert(if_it->ifa_name);
    }
    if (ifaddrs) {
        freeifaddrs(ifaddrs);
    }
    return output;
}
#endif // _WIN32

uint16_t channel_to_mhz(uint16_t channel) {
    return 2407 + (channel * 5);
}

uint16_t mhz_to_channel(uint16_t mhz) {
    return (mhz - 2407) / 5;
}
    
string to_string(PDU::PDUType pduType) {
#define ENUM_TEXT(p) case(PDU::p): return #p;
    switch (pduType){
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
        ENUM_TEXT(PKTAP);
        ENUM_TEXT(MPLS);
        ENUM_TEXT(USER_DEFINED_PDU);
        default: 
            return "";
    }
#undef ENUM_TEXT
}

uint32_t do_checksum(const uint8_t* start, const uint8_t* end) {
    return Endian::host_to_be<uint32_t>(sum_range(start, end));
}

uint16_t sum_range(const uint8_t* start, const uint8_t* end) {
    uint32_t checksum(0);
    const uint8_t* last = end;
    uint16_t buffer = 0;
    uint16_t padding = 0;
    const uint8_t* ptr = start;

    if (((end - start) & 1) == 1) {
        last = end - 1;
        padding = Endian::host_to_le<uint16_t>(*(end - 1));
    }

    while (ptr < last) {
        memcpy(&buffer, ptr, sizeof(uint16_t));
        checksum += buffer;
        ptr += sizeof(uint16_t);
    }

    checksum += padding;
    while (checksum >> 16) {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    return checksum;  
}

template <size_t buffer_size, typename AddressType>
uint32_t generic_pseudoheader_checksum(const AddressType& source_ip, 
                                       const AddressType& dest_ip,
                                       uint16_t len,
                                       uint16_t flag) {
    uint8_t buffer[buffer_size];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write(source_ip);
    stream.write(dest_ip);
    stream.write(Endian::host_to_be(flag));
    stream.write(Endian::host_to_be(len));

    InputMemoryStream input_stream(buffer, sizeof(buffer));
    uint32_t checksum = 0;
    while (input_stream) {
        checksum += input_stream.read<uint16_t>();
    }
    return checksum;
}

uint32_t pseudoheader_checksum(IPv4Address source_ip, 
                               IPv4Address dest_ip,
                               uint16_t len,
                               uint16_t flag) {
    return generic_pseudoheader_checksum<sizeof(uint32_t) * 3>(
        source_ip, dest_ip, len, flag
    );
}

uint32_t pseudoheader_checksum(IPv6Address source_ip,
                               IPv6Address dest_ip,
                               uint16_t len,
                               uint16_t flag) {
    return generic_pseudoheader_checksum<IPv6Address::address_size * 2 + sizeof(uint16_t) * 2>(
        source_ip, dest_ip, len, flag
    );
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

} // Utils
} // Tins
