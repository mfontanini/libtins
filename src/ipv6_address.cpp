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

#include <algorithm>
#include "macros.h"
#ifndef WIN32
    #include <arpa/inet.h>
    #ifdef BSD
        #include <sys/socket.h>
    #endif
#else
    #include <ws2tcpip.h>
    #include <mstcpip.h>
#endif
#include <limits>
#include <sstream>
#include "ipv6_address.h"
#include "address_range.h"

namespace Tins {
const IPv6Address loopback_address = "::1";
const AddressRange<IPv6Address> multicast_range = IPv6Address("ff00::") / 8;

IPv6Address::IPv6Address() {
    std::fill(address, address + address_size, 0);
}

IPv6Address::IPv6Address(const char *addr) {
    init(addr);
}

IPv6Address::IPv6Address(const_iterator ptr) {
    std::copy(ptr, ptr + address_size, address);
}

IPv6Address::IPv6Address(const std::string &addr) {
    init(addr.c_str());
}

void IPv6Address::init(const char *addr) {
    #ifdef WIN32
        // mingw on linux somehow doesn't have InetPton
        #ifdef _MSC_VER
            if(InetPtonA(AF_INET6, addr, address) != 1)
                throw malformed_address();
        #else
            ULONG dummy1;
            USHORT dummy2;
            // Maybe change this, mingw doesn't have any other conversion function
            if(RtlIpv6StringToAddressExA(addr, (IN6_ADDR*)address, &dummy1, &dummy2) != NO_ERROR)
                throw malformed_address();
        #endif
    #else
        if(inet_pton(AF_INET6, addr, address) == 0)
            throw malformed_address();
    #endif            
}

std::string IPv6Address::to_string() const {
    char buffer[INET6_ADDRSTRLEN];
    #ifdef WIN32
        // mingw on linux somehow doesn't have InetNtop
        #ifdef _MSC_VER
            if(InetNtopA(AF_INET6, (PVOID)address, buffer, sizeof(buffer)) != 0)
                throw malformed_address();
        #else
            ULONG sz = sizeof(buffer);
            if(RtlIpv6AddressToStringExA((const IN6_ADDR*)address, 0, 0, buffer, &sz) != NO_ERROR)
                throw malformed_address();
        #endif
    #else
        if(inet_ntop(AF_INET6, address, buffer, sizeof(buffer)) == 0)
            throw malformed_address();
    #endif
    return buffer;
}

bool IPv6Address::is_loopback() const {
    return loopback_address == *this;
}

bool IPv6Address::is_multicast() const {
    return multicast_range.contains(*this);
}
}

