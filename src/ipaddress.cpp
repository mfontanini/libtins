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

#include "ipaddress.h"
#include "utils.h"

using std::string;

Tins::IPv4Address::IPv4Address(uint32_t ip) : ip_addr(ip) {
    
}

Tins::IPv4Address::IPv4Address(const std::string &ip) : 
  ip_addr(Utils::ip_to_int(ip)) {
      
} 

Tins::IPv4Address &Tins::IPv4Address::operator=(uint32_t ip) {
    ip_addr = ip;
    return *this;
}

Tins::IPv4Address &Tins::IPv4Address::operator=(const string &ip) {
    ip_addr = Utils::ip_to_int(ip);
    return *this;
}

Tins::IPv4Address::operator uint32_t() const { 
    return Utils::net_to_host_l(ip_addr); 
}

Tins::IPv4Address::operator std::string() const { 
    return Utils::ip_to_string(ip_addr); 
} 

