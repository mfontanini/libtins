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

#ifndef TINS_UTILS_H
#define TINS_UTILS_H

#include "macros.h"
#include <string>
#include <set>
#include <vector>
#include <stdint.h>
#include "ip_address.h"
#include "ipv6_address.h"
#include "internals.h"

// Fix for Windows interface define on combaseapi.h
#undef interface

namespace Tins {

class NetworkInterface;
class PacketSender;
class PDU;
class IPv6Address;
template <size_t n, typename Storage>
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
 * Struct that represents an entry the routing table
 */
struct RouteEntry {
    /**
     * This interface's name.
     */
    std::string interface;
    
    /**
     * This route entry's destination.
     */
    IPv4Address destination;
    
    /**
     * This route entry's gateway.
     */
    IPv4Address gateway;
    
    /**
     * This route entry's subnet mask.
     */
    IPv4Address mask;

    /**
     * This route entry's metric.
     */
    int metric;
};

/**
 * Struct that represents an entry the IPv6 routing table
 */
struct Route6Entry {
    /**
     * This interface's name.
     */
    std::string interface;

    /**
     * This route entry's destination.
     */
    IPv6Address destination;

    /**
     * This route entry's subnet mask.
     */
    IPv6Address mask;

    /**
     * This route entry's next hop.
     */
    IPv6Address gateway;

    /**
     * This route entry's metric.
     */
    int metric;
};

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

/** \brief List all network interfaces.
 *
 * Returns a set of strings, each of them representing the name
 * of a network interface. These names can be used as the input
 * interface for Utils::interface_ip, Utils::interface_hwaddr, etc.
 */
TINS_API std::set<std::string> network_interfaces();

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
 * \brief Retrieves entries in the routing table.
 * 
 * \brief output ForwardIterator in which entries will be stored.
 */
template<typename ForwardIterator>
void route_entries(ForwardIterator output);

/**
 * \brief Retrieves entries in the routing table.
 * 
 * \return a vector which contains all of the route entries.
 */
TINS_API std::vector<RouteEntry> route_entries();

/**
 * \brief Retrieves entries in the routing table.
 * 
 * \return a vector which contains all of the route entries.
 */
TINS_API std::vector<Route6Entry> route6_entries();

/** \brief Returns the 32 bit crc of the given buffer.
 *
 * \param data The input buffer.
 * \param data_size The size of the input buffer.
 */
TINS_API uint32_t crc32(const uint8_t* data, uint32_t data_size);

/**
 * \brief Converts a channel number to its mhz representation.
 * \param channel The channel number.
 * \return The channel's mhz representation.
 */
TINS_API uint16_t channel_to_mhz(uint16_t channel);

/**
 * \brief Converts mhz units to the appropriate channel number.
 * \param mhz The mhz units to be converted.
 * \return The channel number.
 */
TINS_API uint16_t mhz_to_channel(uint16_t mhz);

/**
 * \brief Converts a PDUType to a string.
 * \param pduType The PDUType to be converted.
 * \return A string representation, for example "DOT11_QOS_DATA".
 */
TINS_API std::string to_string(PDU::PDUType pduType);

/** 
 * \brief Does the 16 bits sum of all 2 bytes elements between start and end.
 *
 * This is the checksum used by IP, UDP and TCP. If there's and odd number of
 * bytes, the last one is padded and added to the checksum. 
 * \param start The pointer to the start of the buffer.
 * \param end The pointer to the end of the buffer(excluding the last element).
 * \return Returns the checksum between start and end (non inclusive) 
 * in network endian
 */
TINS_API uint32_t do_checksum(const uint8_t* start, const uint8_t* end);

/** 
 * \brief Computes the 16 bit sum of the input buffer.
 *
 * If there's and odd number of bytes in the buffer, the last one is padded and 
 * added to the checksum. 
 * \param start The pointer to the start of the buffer.
 * \param end The pointer to the end of the buffer(excluding the last element).
 * \return Returns the checksum between start and end (non inclusive) 
 * in network endian
 */
TINS_API uint16_t sum_range(const uint8_t* start, const uint8_t* end);

/** \brief Performs the pseudo header checksum used in TCP and UDP PDUs.
 *
 * \param source_ip The source ip address.
 * \param dest_ip The destination ip address.
 * \param len The length to be included in the pseudo header.
 * \param flag The flag to use in the protocol field of the pseudo header.
 * \return The pseudo header checksum.
 */
TINS_API uint32_t pseudoheader_checksum(IPv4Address source_ip,
                                        IPv4Address dest_ip,
                                        uint16_t len,
                                        uint16_t flag);

/** \brief Performs the pseudo header checksum used in TCP and UDP PDUs.
 *
 * \param source_ip The source ip address.
 * \param dest_ip The destination ip address.
 * \param len The length to be included in the pseudo header.
 * \param flag The flag to use in the protocol field of the pseudo header.
 * \return The pseudo header checksum.
 */
TINS_API uint32_t pseudoheader_checksum(IPv6Address source_ip,  
                                        IPv6Address dest_ip,
                                        uint16_t len,
                                        uint16_t flag);

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

template<typename ForwardIterator>
void Tins::Utils::route_entries(ForwardIterator output) {
    std::vector<RouteEntry> entries = route_entries();
    for (size_t i = 0; i < entries.size(); ++i) {
        *output = entries[i];
        ++output;
    }
}

#endif // TINS_UTILS_H
