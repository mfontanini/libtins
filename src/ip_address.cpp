/*
 * Copyright (c) 2012, Matias Fontanini
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
#include "ip_address.h"
#include "endianness.h"
#include "address_range.h"

using std::string;

namespace Tins{
const AddressRange<IPv4Address> private_ranges[] = {
    IPv4Address("192.168.0.0") / 16,
    IPv4Address("10.0.0.0") / 8,
    IPv4Address("172.16.0.0") / 12
};

const AddressRange<IPv4Address> loopback_range = IPv4Address("127.0.0.0") / 8;
const AddressRange<IPv4Address> multicast_range = IPv4Address("224.0.0.0") / 4;
    
IPv4Address::IPv4Address(uint32_t ip) 
: ip_addr(Endian::be_to_host(ip)) {
    
}

IPv4Address::IPv4Address(const char *ip) {
    ip_addr = ip ? ip_to_int(ip) : 0; 
}

IPv4Address::IPv4Address(const std::string &ip) 
: ip_addr(ip_to_int(ip)) {
      
} 

IPv4Address::operator uint32_t() const { 
    return Endian::host_to_be(ip_addr); 
}

std::string IPv4Address::to_string() const {
    std::ostringstream oss;
    oss << *this;
    return oss.str();
}

uint32_t IPv4Address::ip_to_int(const string &ip) {
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

std::ostream &operator<<(std::ostream &output, const IPv4Address &addr) {
    int mask(24);
    uint32_t ip_addr = addr.ip_addr;
    while(mask >=0) {
        output << ((ip_addr >> mask) & 0xff);
        if(mask)
            output <<  '.';
        mask -= 8;
    }
    return output;;
}

bool IPv4Address::is_private() const {
    const AddressRange<IPv4Address> *iter = private_ranges;
    while(iter != private_ranges + 3) {
        if(iter->contains(*this))
            return true;
        ++iter;
    }
    return false;
}

bool IPv4Address::is_loopback() const {
    return loopback_range.contains(*this);
}

bool IPv4Address::is_multicast() const {
    return multicast_range.contains(*this);
}
}
