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

#ifndef TINS_IPADDRESS_H
#define TINS_IPADDRESS_H

#include <string>
#include <iostream>
#include <stdint.h>

namespace Tins {
    class IPv4Address {
    public:
        IPv4Address(const char *ip = 0);
        IPv4Address(const std::string &ip);
        explicit IPv4Address(uint32_t ip);
        
        IPv4Address &operator=(uint32_t ip);
        IPv4Address &operator=(const std::string &ip);
        
        operator uint32_t() const;
        
        std::string to_string() const;
        
        bool operator==(const IPv4Address &rhs) const {
            return ip_addr == rhs.ip_addr;
        }
        
        bool operator!=(const std::string &rhs) const {
            return !(*this == rhs);
        }
        
        friend std::ostream &operator<<(std::ostream &output, const IPv4Address &addr) {
            return output << addr.to_string();
        }
    private:
        uint32_t ip_to_int(const std::string &ip);
    
        uint32_t ip_addr;
    };
};


#endif // TINS_IPADDRESS_H
