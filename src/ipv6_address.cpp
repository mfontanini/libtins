/*
 * Copyright (c) 2016, Matias Fontanini
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
#ifndef _WIN32
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
#include "exceptions.h"

using std::fill;
using std::string;

namespace Tins {

const IPv6Address loopback_address = "::1";
const AddressRange<IPv6Address> multicast_range = IPv6Address("ff00::") / 8;

IPv6Address IPv6Address::from_prefix_length(uint32_t prefix_length) {
    IPv6Address address;
    IPv6Address::iterator it = address.begin();
    while (prefix_length > 8) {
        *it = 0xff;
        ++it;
        prefix_length -= 8;
    }
    *it = 0xff << (8 - prefix_length);
    return address;
}

IPv6Address::IPv6Address() {
    fill(address_, address_ + address_size, 0);
}

IPv6Address::IPv6Address(const char* addr) {
    init(addr);
}

IPv6Address::IPv6Address(const_iterator ptr) {
    std::copy(ptr, ptr + address_size, address_);
}

IPv6Address::IPv6Address(const std::string& addr) {
    init(addr.c_str());
}

void IPv6Address::init(const char* addr) {
    #ifdef _WIN32
        // mingw on linux somehow doesn't have InetPton
        #ifdef _MSC_VER
            if (InetPtonA(AF_INET6, addr, address_) != 1) {
                throw invalid_address();
            }
        #else
            ULONG dummy1;
            USHORT dummy2;
            // Maybe change this, mingw doesn't have any other conversion function
            if (RtlIpv6StringToAddressExA(addr, (IN6_ADDR*)address_, &dummy1, &dummy2) != NO_ERROR) {
                throw invalid_address();
            }
        #endif
    #else
        if (inet_pton(AF_INET6, addr, address_) == 0) {
            throw invalid_address();
        }
    #endif            
}

string IPv6Address::to_string() const {
    char buffer[INET6_ADDRSTRLEN];
    #ifdef _WIN32
        // mingw on linux somehow doesn't have InetNtop
        #ifdef _MSC_VER
            if (InetNtopA(AF_INET6, (PVOID)address_, buffer, sizeof(buffer)) == 0) {
                throw invalid_address();
            }
        #else
            ULONG sz = sizeof(buffer);
            if (RtlIpv6AddressToStringExA((const IN6_ADDR*)address_, 0, 0, buffer, &sz) != NO_ERROR) {
                throw invalid_address();
            }
        #endif
    #else
        if (inet_ntop(AF_INET6, address_, buffer, sizeof(buffer)) == 0) {
            throw invalid_address();
        }
    #endif
    return buffer;
}

bool IPv6Address::is_loopback() const {
    return loopback_address == *this;
}

bool IPv6Address::is_multicast() const {
    return multicast_range.contains(*this);
}

IPv6Address operator&(const IPv6Address& lhs, const IPv6Address& rhs) {
    IPv6Address output = lhs;
    IPv6Address::iterator addr_iter = output.begin();
    for (IPv6Address::const_iterator it = rhs.begin(); it != rhs.end(); ++it, ++addr_iter) {
        *addr_iter = *addr_iter & *it;
    }
    return output;
}

} // Tins
