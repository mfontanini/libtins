/*
 * Copyright (c) 2017, Matias Fontanini
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
#include <cstring>
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
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #undef interface
#endif
#include "utils.h"
#include "arp.h"
#include "ethernetII.h"
#include "network_interface.h"
#include "packet_sender.h"
#include "cxxstd.h"
#include "hw_address.h"
#include "memory_helpers.h"
#include "detail/smart_ptr.h"
#include "detail/smart_ptr.h"

using std::string;
using std::istream;
using std::set;
using std::vector;
using std::back_inserter;
using std::runtime_error;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

/** \cond */

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
    NetworkInterface::Info info(iface.addresses());
    #ifdef _WIN32
        // On Windows, use SendARP
        IPAddr source;
        IPAddr dest;
        ULONG hw_address[2];
        ULONG address_length = 6;
        source = static_cast<uint32_t>(info.ip_addr);
        dest = static_cast<uint32_t>(ip);
        if (SendARP(dest, source, &hw_address, &address_length) == NO_ERROR && address_length == 6) {
            return HWAddress<6>((const uint8_t*)hw_address);
        }
    #else
        // On other platforms, just do the ARP resolution ourselves
        EthernetII packet = ARP::make_arp_request(ip, info.ip_addr, info.hw_addr);
        Internals::smart_ptr<PDU>::type response(sender.send_recv(packet, iface));
        if (response.get()) {
            const ARP* arp_resp = response->find_pdu<ARP>();
            if (arp_resp) {
                return arp_resp->sender_hw_addr();
            }
        }
    #endif 
    throw runtime_error("Could not resolve hardware address");
}

HWAddress<6> resolve_hwaddr(IPv4Address ip, PacketSender& sender) {
    return resolve_hwaddr(sender.default_interface(), ip, sender);
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

} // Utils
} // Tins
