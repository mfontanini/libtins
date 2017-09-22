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

#ifndef TINS_RESOLVE_UTILS_H
#define TINS_RESOLVE_UTILS_H

#include <string>
#include <tins/macros.h>

namespace Tins {

class PacketSender;
class NetworkInterface;
class IPv4Address;
class IPv6Address;
template <size_t n>
class HWAddress;

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

} // Utils
} // Tins

#endif // TINS_RESOLVE_UTILS_H
