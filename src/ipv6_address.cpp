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

#include <algorithm>
#ifndef WIN32
    #include <arpa/inet.h>
#endif
#include <limits>
#include <iostream> // borrame
#include <sstream>
#include "ipv6_address.h"

namespace Tins {
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
        if(inet_pton(AF_INET6, addr, address) == 0)
            throw malformed_address();
    }

    std::string IPv6Address::to_string() const {
        char buffer[INET6_ADDRSTRLEN];
        if(inet_ntop(AF_INET6, address, buffer, sizeof(buffer)) == 0)
            throw malformed_address();
        return buffer;
    }
    
}

