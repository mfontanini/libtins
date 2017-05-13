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

#include "utils/resolve_utils.h"
 #ifndef _WIN32
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <sys/socket.h>
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
#include "exceptions.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "hw_address.h"
#include "ethernetII.h"
#include "arp.h"
#include "packet_sender.h"
#include "network_interface.h"
#include "detail/smart_ptr.h"

using std::string;

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
        throw Tins::exception_base("Could not resolve address");
    }
}

/** \endcond */

namespace Tins {
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
    throw exception_base("Could not resolve hardware address");
}

HWAddress<6> resolve_hwaddr(IPv4Address ip, PacketSender& sender) {
    return resolve_hwaddr(sender.default_interface(), ip, sender);
}


} // Utils
} // Tins
