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

#ifndef TINS_IPADDRESS_H
#define TINS_IPADDRESS_H

#include <string>
#include <iostream>
#include <stdint.h>
#include "cxxstd.h"

namespace Tins {
/**
 * \class IPv4Address
 * \brief Abstraction of an IPv4 address.
 */
class IPv4Address {
public:
    /**
     * The address size.
     */
    static const size_t address_size = sizeof(uint32_t);

    /**
     * The broadcast address.
     */
    static const IPv4Address broadcast;

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
     * \brief Compare this IPv4Address for less-than inequality.
     * 
     * \param rhs The address to be compared.
     * \return bool indicating whether this address is less-than rhs.
     */
    bool operator< (const IPv4Address &rhs) const {
        return ip_addr < rhs.ip_addr;
    }
    
    /**
     * \brief Returns true if this is a private IPv4 address.
     * 
     * This takes into account the private network ranges defined in
     * RFC 1918. Therefore, this method returns true if this address
     * is in any of the following network ranges, false otherwise:
     * 
     * - 192.168.0.0/16
     * - 10.0.0.0/8
     * - 172.16.0.0/12
     */
    bool is_private() const;
    
    /**
     * \brief Returns true if this is a loopback IPv4 address.
     * 
     * This method returns true if this address is in the address range
     * 127.0.0.0/8, false otherwise.
     */
    bool is_loopback() const;

    /**
     * \brief Returns true if this is a multicast IPv4 address.
     * 
     * This method returns true if this address is in the address range
     * 224.0.0.0/4, false otherwise.
     */
    bool is_multicast() const;

    /**
     * \brief Returns true if this is an unicast IPv4 address.
     */
    bool is_unicast() const;

    /**
     * \brief Returns true if this is a broadcast IPv4 address.
     */
    bool is_broadcast() const;
    
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
    uint32_t ip_to_int(const char* ip);

    uint32_t ip_addr;
};
} //namespace Tins

#if TINS_IS_CXX11
namespace std
{
template<>
struct hash<Tins::IPv4Address> {
    size_t operator()(const Tins::IPv4Address &addr) const {
        return std::hash<uint32_t>()(addr);
    }
};
} // namespace std
#endif


#endif // TINS_IPADDRESS_H
