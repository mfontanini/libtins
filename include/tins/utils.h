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

#ifndef TINS_UTILS_H
#define TINS_UTILS_H

#include "macros.h"
#include <string>
#include <stdint.h>
#include "ip_address.h"
#include "ipv6_address.h"
#include "pdu.h"
#include "detail/type_traits.h"
#include "utils/checksum_utils.h"
#include "utils/frequency_utils.h"
#include "utils/routing_utils.h"

// Fix for Windows interface define on combaseapi.h
#undef interface

namespace Tins {

class NetworkInterface;
class PacketSender;
class PDU;
class IPv6Address;
template <size_t n>
class HWAddress;

/** 
 * \brief Network utils namespace.
 *
 * This namespace provides utils to convert between integer IP addresses
 * and dotted notation strings, "net to host" integer conversions, 
 * interface listing, etc.
 */
namespace Utils {

/** 
 * \brief Resolves a domain name and returns its corresponding ip address.
 *
 * If an ip address is given, its integer representation is returned.
 * Otherwise, the domain name is resolved and its ip address is returned.
 *
 * \param to_resolve The domain name/ip address to resolve.
 */
TINS_API IPv4Address resolve_domain(const std::string& to_resolve);

/** 
 * \brief Resolves a domain name and returns its corresponding ip address.
 *
 * If an ip address is given, its integer representation is returned.
 * Otherwise, the domain name is resolved and its ip address is returned.
 *
 * \param to_resolve The domain name/ip address to resolve.
 */
TINS_API IPv6Address resolve_domain6(const std::string& to_resolve);

/** 
 * \brief Resolves the hardware address for a given ip.
 *
 * If the address can't be resolved, a std::runtime_error
 * exception is thrown.
 * 
 * \param iface The interface in which the packet will be sent.
 * \param ip The ip to resolve, in integer format.
 * \param sender The sender to use to send and receive the ARP requests.
 * \return HWAddress<6> containing the resolved hardware address.
 */
TINS_API HWAddress<6> resolve_hwaddr(const NetworkInterface& iface, 
                                     IPv4Address ip,
                                     PacketSender& sender);

/** 
 * \brief Resolves the hardware address for a given ip.
 *
 * If the address can't be resolved, a std::runtime_error
 * exception is thrown.
 * 
 * This method sends and receives the packet through
 * PacketSender::default_interface.
 * 
 * \param ip The ip to resolve, in integer format.
 * \param sender The sender to use to send and receive the ARP requests.
 * \return HWAddress<6> containing the resolved hardware address.
 */
TINS_API HWAddress<6> resolve_hwaddr(IPv4Address ip, PacketSender& sender);

/**
 * \brief Finds the gateway's IP address for the given IP 
 * address.
 * 
 * \param ip The IP address for which the default gateway will
 * be searched.
 * \param gw_addr This parameter will contain the gateway's IP
 * address in case it is found.
 * 
 * \return bool indicating whether the lookup was successfull.
 */
TINS_API bool gateway_from_ip(IPv4Address ip, IPv4Address& gw_addr);

/**
 * \brief Converts a PDUType to a string.
 * \param pduType The PDUType to be converted.
 * \return A string representation, for example "DOT11_QOS_DATA".
 */
TINS_API std::string to_string(PDU::PDUType pduType);

template <typename T>
struct is_pdu {  
    template <typename U>
    static char test(typename U::PDUType*);
     
    template <typename U>
    static long test(...);
 
    static const bool value = sizeof(test<T>(0)) == 1;
};

/**
 * Returns the argument.
 */
inline PDU& dereference_until_pdu(PDU& pdu) {
    return pdu;
}

/**
 * \brief Dereferences the parameter until a PDU is found.
 * 
 * This function dereferences the parameter until a PDU object
 * is found. When it's found, it is returned. 
 * 
 * \param value The parameter to be dereferenced.
 */
template<typename T> 
inline typename Internals::enable_if<!is_pdu<T>::value, PDU&>::type 
dereference_until_pdu(T& value) {
    return dereference_until_pdu(*value);
}

} // Utils
} // Tins

#endif // TINS_UTILS_H
