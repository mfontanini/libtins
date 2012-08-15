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

#ifndef __UTILS_H
#define __UTILS_H

#include <stdexcept>

#ifndef WIN32
    #include <ifaddrs.h>
    #include <endian.h>
#endif
#include <string>
#include <set>
#include <fstream>
#include <stdint.h>
#include "packetsender.h"
#include "ipaddress.h"
#include "hwaddress.h"
#include "network_interface.h"

namespace Tins {
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
         * \brief Convert a dotted-ip-notation string to an integer.
         *
         * \param ip A dotted ip notation string
         */
        uint32_t ip_to_int(const std::string &ip) throw (std::runtime_error);

        /** 
         * \brief Convert an integer ip to a dotted-ip-notation string.
         *
         * \param ip An integer ip.
         */
        std::string ip_to_string(uint32_t ip);

        /** 
         * \brief Resolves a domain name and returns its corresponding ip address.
         *
         * If an ip address is given, its integer representation is returned.
         * Otherwise, the domain name is resolved and its ip address is returned.
         *
         * \param to_resolve The domain name/ip address to resolve.
         */
        uint32_t resolve_ip(const std::string &to_resolve);
        
        /**
         * \brief Pings an ip address.
         * 
         * This function pings an IP address and returns the ICMP response.
         * If no response is received, 0 is returned
         * 
         * \param ip The IP address to ping.
         * \param sender The PacketSender that will send the ping request.
         * \param ip_src The source IP address that will be used in the packet.
         * If 0, or no parameter is provided, then that IP address is looked
         * up using Utils::interface_ip.
         * 
         * \return PDU * containing either 0 if no response was received,
         * or the ICMP response otherwise.
         */
        PDU *ping_address(IPv4Address ip, PacketSender *sender, IPv4Address ip_src = 0);

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
          HWAddress<6> *address, PacketSender *sender);

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
        
        /** 
         * \brief Changes a 16-bit integral value's endianess.
         *
         * \param data The data to convert.
         */
        inline uint16_t change_endian(uint16_t data) {
            return ((data & 0xff00) >> 8)  | ((data & 0x00ff) << 8);
        }
        
        /**
         * \brief Changes a 32-bit integral value's endianess.
         *
         * \param data The data to convert.
         */
        inline uint32_t change_endian(uint32_t data) {
            return (((data & 0xff000000) >> 24) | ((data & 0x00ff0000) >> 8)  |
                    ((data & 0x0000ff00) << 8)  | ((data & 0x000000ff) << 24));
        }
        
        /**
         * \brief Changes a 64-bit integral value's endianess.
         *
         * \param data The data to convert.
         */
         inline uint64_t change_endian(uint64_t data) {
            return (((uint64_t)(change_endian((uint32_t)((data << 32) >> 32))) << 32) |
                    (change_endian(((uint32_t)(data >> 32)))));
         }
        
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            /** 
             * \brief Convert any integral type to big endian.
             *
             * \param data The data to convert.
             */
            template<typename T>
            inline T to_be(T data) {
                return change_endian(data);
            }
             
            /**
             * \brief Convert any integral type to little endian.
             *
             * On little endian platforms, the parameter is simply returned.
             * 
             * \param data The data to convert.
             */
             template<typename T>
             inline T to_le(T data) {
                 return data;
             }
             
            /**
             * \brief Convert any big endian value to the host's endianess.
             * 
             * \param data The data to convert.
             */
             template<typename T>
             inline T be_to_host(T data) {
                 return change_endian(data);
             }
             
            /**
             * \brief Convert any little endian value to the host's endianess.
             * 
             * \param data The data to convert.
             */
             template<typename T>
             inline T le_to_host(T data) {
                 return data;
             }
        #elif __BYTE_ORDER == __BIG_ENDIAN
            /** 
             * \brief Convert any integral type to big endian.
             *
             * \param data The data to convert.
             */
            template<typename T>
            inline T to_be(T data) {
                return data;
            }
             
            /**
             * \brief Convert any integral type to little endian.
             *
             * On little endian platforms, the parameter is simply returned.
             * 
             * \param data The data to convert.
             */
             template<typename T>
             inline T to_le(T data) {
                 return change_endian(data);
             }
             
            /**
             * \brief Convert any big endian value to the host's endianess.
             * 
             * \param data The data to convert.
             */
             template<typename T>
             inline T be_to_host(T data) {
                 return data;
             }
             
            /**
             * \brief Convert any little endian value to the host's endianess.
             * 
             * \param data The data to convert.
             */
             template<typename T>
             inline T le_to_host(T data) {
                 return change_endian(data);
             }
        #endif

        /** \brief Convert 16 bit integer into network byte order.
         *
         * \param data The data to convert.
         */
        inline uint16_t net_to_host_s(uint16_t data) {
            return ((data & 0xff00) >> 8)  | ((data & 0x00ff) << 8);
        }

        /**
         * \brief Convert 32 bit integer into network byte order.
         *
         * \param data The data to convert.
         */
        inline uint32_t net_to_host_l(uint32_t data) {
            return (((data & 0xff000000) >> 24) | ((data & 0x00ff0000) >> 8)  |
                    ((data & 0x0000ff00) << 8)  | ((data & 0x000000ff) << 24));
        }

        /**
         * \brief Convert 64 bit integer into network byte order.
         *
         * \param data The data to convert.
         */
        inline uint64_t net_to_host_ll(uint64_t data) {
            return (((uint64_t)(net_to_host_l((uint32_t)((data << 32) >> 32))) << 32) |
                    (net_to_host_l(((uint32_t)(data >> 32)))));
        }

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
        entry.destination = net_to_host_l(dummy);
        from_hex(mask, dummy);
        entry.mask = net_to_host_l(dummy);
        from_hex(gw, dummy);
        entry.gateway = net_to_host_l(dummy);
        skip_line(input);
        *output = entry;
        ++output;
    }
}

#endif
