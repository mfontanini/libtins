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
    /**
     * \class IPv4Address
     * \brief Abstraction of an IPv4 address.
     */
    class IPv4Address {
    public:
        /**
         * \brief Constructor taking a const char*.
         * 
         * Constructs an IPv4Address from a dotted-notation address 
         * cstring. If the pointer provided is null, then a default 
         * IPv4Address object is constructed, which corresponds to 
         * the 0.0.0.0 address.
         * 
         * \param ip const char* containing the dotted-notation address.
         */
        IPv4Address(const char *ip = 0);
        
        /**
         * \brief Constructor taking a std::string.
         * 
         * Constructs an IPv4Address from a dotted-notation std::strings
         * 
         * \param ip std::string containing the dotted-notation address.
         */
        IPv4Address(const std::string &ip);
        
        /**
         * \brief Constructor taking a IP address represented as a
         * big endian integer.
         * 
         * This constructor should be used internally by PDUs that
         * handle IP addresses. The provided integer <b>must</b> be
         * be in big endian.
         */
        explicit IPv4Address(uint32_t ip);
        
        /**
         * \brief User defined conversion to big endian integral value.
         */
        operator uint32_t() const;
        
        /**
         * \brief Retrieve the string representation of this address.
         * 
         * \return std::string containing the representation of this address.
         */
        std::string to_string() const;
        
        /**
         * \brief Compare this IPv4Address for equality.
         * 
         * \param rhs The address to be compared.
         * \return bool indicating whether this address equals rhs.
         */
        bool operator==(const IPv4Address &rhs) const {
            return ip_addr == rhs.ip_addr;
        }
        
        /**
         * \brief Compare this IPv4Address for inequality.
         * 
         * \param rhs The address to be compared.
         * \return bool indicating whether this address is distinct 
         * from rhs.
         */
        bool operator!=(const IPv4Address &rhs) const {
            return !(*this == rhs);
        }
        
        /**
         * \brief Writes this address to a std::ostream.
         * 
         * This method writes addr in a dotted-string notation address
         * to the std::ostream argument.
         * 
         * \param output The std::ostream in which to write the address.
         * \param addr The IPv4Address to be written.
         * \return std::stream& pointing to output.
         */
        friend std::ostream &operator<<(std::ostream &output, const IPv4Address &addr);
    private:
        uint32_t ip_to_int(const std::string &ip);
    
        uint32_t ip_addr;
    };
};


#endif // TINS_IPADDRESS_H
