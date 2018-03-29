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

#ifndef TINS_ROUTING_UTILS_H
#define TINS_ROUTING_UTILS_H

#include <vector>
#include <set>
#include <tins/macros.h>
#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

// Fix for Windows interface define on combaseapi.h
#undef interface

namespace Tins {
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
 * \brief Retrieves entries in the routing table.
 * 
 * \brief output ForwardIterator in which entries will be stored.
 */
template<typename ForwardIterator>
void route_entries(ForwardIterator output);

/**
 * \brief Retrieves entries in the routing table.
 *
 * \brief output ForwardIterator in which entries will be stored.
 */
template<typename ForwardIterator>
void route6_entries(ForwardIterator output);

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

/**
 * \brief List all network interfaces.
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
TINS_API bool gateway_from_ip(IPv6Address ip, IPv6Address& gw_addr);

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

template<typename ForwardIterator>
void Tins::Utils::route6_entries(ForwardIterator output) {
    std::vector<Route6Entry> entries = route6_entries();
    for (size_t i = 0; i < entries.size(); ++i) {
        *output = entries[i];
        ++output;
    }
}

#endif // TINS_ROUTING_UTILS_H
