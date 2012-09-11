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

#ifndef TINS_UTILS_H
#define TINS_UTILS_H

#ifndef WIN32
    #include <ifaddrs.h>
#endif
#include <string>
#include <set>
#include <fstream>
#include <stdint.h>
#include "ip_address.h"
#include "hw_address.h"

namespace Tins {
    class NetworkInterface;
    class PacketSender;
    class PDU;
    
    /** 
     * \brief Network utils namespace.
     *
     * This namespace provides utils to convert between integer IP addresses
     * and dotted notation strings, "net to host" integer conversions, 
     * interface listing, etc.
     */
    namespace Utils {
        /**
         * Struct that represents an entry in /proc/net/route
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
        };

        /** 
         * \brief Resolves a domain name and returns its corresponding ip address.
         *
         * If an ip address is given, its integer representation is returned.
         * Otherwise, the domain name is resolved and its ip address is returned.
         *
         * \param to_resolve The domain name/ip address to resolve.
         */
        IPv4Address resolve_ip(const std::string &to_resolve);

        /** \brief Resolves the hardware address for a given ip.
         *
         * \param iface The interface in which the packet will be sent.
         * \param ip The ip to resolve, in integer format.
         * \param buffer The buffer in which the host's hardware address will be stored.
         * \param sender The sender to use to send and receive the ARP requests.
         * \return Returns true if the hardware address was resolved successfully,
         * false otherwise.
         */
        bool resolve_hwaddr(const NetworkInterface &iface, IPv4Address ip, 
          HWAddress<6> *address, PacketSender &sender);

        /** \brief List all network interfaces.
         *
         * Returns a set of strings, each of them representing the name
         * of a network interface. These names can be used as the input
         * interface for Utils::interface_ip, Utils::interface_hwaddr, etc.
         */
        std::set<std::string> network_interfaces();
        
        /**
         * \brief Finds the gateway's IP address for the given IP 
         * address.
         * 
         * \param ip The IP address for which the default gateway will
         * be searched.
         * \param gw_addr This parameter will contain the gateway's IP
         * address in case it is found.
         * 
         * \return bool indicating wether the lookup was successfull.
         */
        bool gateway_from_ip(IPv4Address ip, IPv4Address &gw_addr);
        
        
        /**
         * \brief Retrieves entries int the routing table.
         * 
         * \brief output ForwardIterator in which entries will be stored.
         */
        template<class ForwardIterator>
        void route_entries(ForwardIterator output);

        /** \brief Returns the 32 bit crc of the given buffer.
         *
         * \param data The input buffer.
         * \param data_size The size of the input buffer.
         */
        uint32_t crc32(const uint8_t* data, uint32_t data_size);

        /**
         * \brief Converts a channel number to its mhz representation.
         * \param channel The channel number.
         * \return The channel's mhz representation.
         */
        uint16_t channel_to_mhz(uint16_t channel);

        /** \brief Does the 16 bits sum of all 2 bytes elements between start and end.
         *
         * This is the checksum used by IP, UDP and TCP. If there's and odd number of
         * bytes, the last one is padded and added to the checksum. The checksum is performed
         * using network endiannes.
         * \param start The pointer to the start of the buffer.
         * \param end The pointer to the end of the buffer(excluding the last element).
         * \return Returns the checksum between start and end(non inclusive).
         */
        uint32_t do_checksum(const uint8_t *start, const uint8_t *end);

        /** \brief Performs the pseudo header checksum used in TCP and UDP PDUs.
         *
         * \param source_ip The source ip address.
         * \param dest_ip The destination ip address.
         * \param len The length to be included in the pseudo header.
         * \param flag The flag to use in the protocol field of the pseudo header.
         * \return The pseudo header checksum.
         */
        uint32_t pseudoheader_checksum(IPv4Address source_ip, IPv4Address dest_ip, uint32_t len, uint32_t flag);

        /** \brief Generic function to iterate through interface and collect
         * data.
         *
         * The parameter is applied to every interface found, allowing
         * the object to collect data from them.
         * \param functor An instance of an class which implements operator(struct ifaddrs*).
         */
        template<class Functor> 
        void generic_iface_loop(Functor &functor) {
            struct ifaddrs *ifaddrs = 0;
            struct ifaddrs *if_it = 0;
            getifaddrs(&ifaddrs);
            for(if_it = ifaddrs; if_it; if_it = if_it->ifa_next) {
                if(functor(if_it))
                    break;
            }
            if(ifaddrs)
                freeifaddrs(ifaddrs);
        }
        
        namespace Internals {
            void skip_line(std::istream &input);
            bool from_hex(const std::string &str, uint32_t &result);
        }
    }
}

template<class ForwardIterator>
void Tins::Utils::route_entries(ForwardIterator output) {
    using namespace Utils::Internals;
    std::ifstream input("/proc/net/route");
    std::string destination, mask, gw;
    uint32_t dummy;
    skip_line(input);
    RouteEntry entry;
    while(input >> entry.interface >> destination >> gw) {
        for(unsigned i(0); i < 5; ++i)
            input >> mask;
        from_hex(destination, dummy);
        entry.destination = IPv4Address(dummy);
        from_hex(mask, dummy);
        entry.mask = IPv4Address(dummy);
        from_hex(gw, dummy);
        entry.gateway = IPv4Address(dummy);
        skip_line(input);
        *output = entry;
        ++output;
    }
}

#endif // TINS_UTILS_H
