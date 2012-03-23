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
#endif
#include <string>
#include <set>
#include <stdint.h>
#include "packetsender.h"

namespace Tins {
    /** \brief Network utils namespace.
     *
     * This namespace provides utils to convert between integer IP addresses
     * and dotted notation strings, hw addresses, "net to host" integer
     * conversions, interface listing, etc.
     */
    namespace Utils {
        /**
         * \brief Struct that represents an interface's information.
         */
        struct InterfaceInfo {
            uint32_t ip_addr, netmask, bcast_addr;
            uint8_t hw_addr[6];
        };
        
        /** \brief Convert a dotted-ip-notation string to an integer.
         *
         * \param ip A dotted ip notation string
         */
        uint32_t ip_to_int(const std::string &ip) throw (std::runtime_error);

        /** \brief Convert an integer ip to a dotted-ip-notation string.
         *
         * \param ip An integer ip.
         */
        std::string ip_to_string(uint32_t ip);

        /** \brief Converts a hardware address string into a byte array.
         *
         * The hardware address must be formatted using the notation 'HH:HH:HH:HH:HH:HH'.
         * Where H is a hexadecimal character(0-9, a-f).
         *
         * \param hw_addr The harware address string.
         * \param array The output buffer. It must be at least 6 bytes long.
         */
        bool hwaddr_to_byte(const std::string &hw_addr, uint8_t *array);

        /** \brief Converts a byte array representing a hardware address
         * into a string.
         *
         * The input buffer must be at least 6 bytes long.
         * \param array The input buffer.
         */
        std::string hwaddr_to_string(const uint8_t *array);

        /** \brief Resolves a domain name and returns its corresponding ip address.
         *
         * If an ip address is given, its integer representation is returned.
         * Otherwise, the domain name is resolved and its ip address is returned.
         *
         * \param to_resolve The domain name/ip address to resolve.
         */
        uint32_t resolve_ip(const std::string &to_resolve) throw (std::runtime_error);
        
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
        PDU *ping_address(uint32_t ip, PacketSender *sender, uint32_t ip_src = 0);

        /** \brief Resolves the hardware address for a given ip.
         *
         * \param iface The interface in which the packet will be sent.
         * \param ip The ip to resolve, in integer format.
         * \param buffer The buffer in which the host's hardware address will be stored.
         * \param sender The sender to use to send and receive the ARP requests.
         * \return Returns true if the hardware address was resolved successfully,
         * false otherwise.
         */
        bool resolve_hwaddr(const std::string &iface, uint32_t ip, uint8_t *buffer, PacketSender *sender);

        /** \brief List all network interfaces.
         *
         * Returns a set of strings, each of them representing the name
         * of a network interface. These names can be used as the input
         * interface for Utils::interface_ip, Utils::interface_hwaddr, etc.
         */
        std::set<std::string> network_interfaces();

        /**
         * \brief Lookup the ip address of the given interface.
         *
         * If the lookup fails, false will be returned, true otherwise.
         * \param iface The interface from which to extract the ip address.
         * \param ip The ip address found will be returned in this param.
         * 
         * \return bool indicating wether the operation was successfull.
         */
        bool interface_ip(const std::string &iface, uint32_t &ip);
        
        /**
         * \brief Lookup the ip/hw/netmask/broadcast address of the 
         * given interface.
         *
         * If the lookup fails, false will be returned, true otherwise.
         * \param iface The interface from which to extract the ip address.
         * \param info The InterfaceInfo in which the information will
         * be stored.
         * 
         * \return bool indicating wether the operation was successfull.
         */
        bool interface_info(const std::string &iface, InterfaceInfo &info);

        /**
         * \brief Lookup the hardware address of the given interface.
         *
         * If the lookup fails, false will be returned, true otherwise.
         * \param iface The interface from which to extract the hardware address.
         * \param buffer The hw address will be stored in this buffer. It must
         * be at least 6 bytes long.
         * 
         * \return bool indicating wether the operation was successfull.
         */
        bool interface_hwaddr(const std::string &iface, uint8_t *buffer);

        /**
         * \brief Lookup the interface identifier.
         *
         * If the lookup fails, false will be returned, true otherwise.
         * \param iface The interface from which to extract the identifier.
         * \param id The interface id will be returned in this parameter.
         * 
         * \return bool indicating wether the operation was successfull.
         */
        bool interface_id(const std::string &iface, uint32_t &id);

        /**
         * \brief Finds the gateway interface matching the given ip.
         *
         * This function find the interface which would be the gateway
         * when sending a packet to the given ip.
         * \param ip The ip of the interface we are looking for.
         * \return The interface's name.
         */
        std::string interface_from_ip(uint32_t ip);
        
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
        bool gateway_from_ip(uint32_t ip, uint32_t &gw_addr) ;
        

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
        uint32_t pseudoheader_checksum(uint32_t source_ip, uint32_t dest_ip, uint32_t len, uint32_t flag);

        /** \brief Generic function to iterate through interface and collect
         * data.
         *
         * The parameter is applied to every interface found, allowing
         * the object to collect data from them.
         * \param functor An instance of an class which implements operator(struct ifaddrs*).
         */
        template<class T> void generic_iface_loop(T &functor) {
            struct ifaddrs *ifaddrs = 0;
            struct ifaddrs *if_it = 0;
            getifaddrs(&ifaddrs);
            for(if_it = ifaddrs; if_it; if_it = if_it->ifa_next)
                functor(if_it);
            if(ifaddrs)
                freeifaddrs(ifaddrs);
        }
    };
};

#endif
