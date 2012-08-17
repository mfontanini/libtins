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
#include "ipaddress.h"
#include "utils.h"

using std::string;

namespace Tins{
IPv4Address::IPv4Address(uint32_t ip) : ip_addr(ip) {
    
}

IPv4Address::IPv4Address(const std::string &ip) 
: ip_addr(Utils::ip_to_int(ip)) {
      
} 

IPv4Address &IPv4Address::operator=(uint32_t ip) {
    ip_addr = ip;
    return *this;
}

IPv4Address &Tins::IPv4Address::operator=(const string &ip) {
    ip_addr = Utils::ip_to_int(ip);
    return *this;
}

IPv4Address::operator uint32_t() const { 
    return Utils::host_to_be(ip_addr); 
}

IPv4Address::operator std::string() const { 
    return Utils::ip_to_string(ip_addr); 
} 

std::string IPv4Address::to_string() const {
    return Utils::ip_to_string(ip_addr); 
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
}
