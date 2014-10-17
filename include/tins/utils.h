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

#ifndef TINS_UTILS_H
#define TINS_UTILS_H

#ifndef WIN32
    #include <ifaddrs.h>
#else
    #include <winsock2.h>
    #include <iphlpapi.h>
    #undef interface
    #include "network_interface.h"
#endif
#include "macros.h"
#if defined(BSD) || defined(__FreeBSD_kernel__)
    #include <sys/file.h>
    #include <sys/socket.h>
    #include <sys/sysctl.h>

    #include <net/if.h>
    #include <net/route.h>
    #include <netinet/in.h>
#endif
#include <string>
#include <set>
#include <fstream>
#include <vector>
#include <stdint.h>
#include "ip_address.h"
#include "ipv6_address.h"
#include "hw_address.h"
#include "internals.h"

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
        IPv4Address resolve_domain(const std::string &to_resolve);
        
        /** 
         * \brief Resolves a domain name and returns its corresponding ip address.
         *
         * If an ip address is given, its integer representation is returned.
         * Otherwise, the domain name is resolved and its ip address is returned.
         *
         * \param to_resolve The domain name/ip address to resolve.
         */
        IPv6Address resolve_domain6(const std::string &to_resolve);
        
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
        HWAddress<6> resolve_hwaddr(const NetworkInterface &iface, 
          IPv4Address ip, PacketSender &sender);
        
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
        HWAddress<6> resolve_hwaddr(IPv4Address ip, PacketSender &sender);

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
         * \brief Retrieves entries in the routing table.
         * 
         * \brief output ForwardIterator in which entries will be stored.
         */
        template<class ForwardIterator>
        void route_entries(ForwardIterator output);

        /**
         * \brief Retrieves entries in the routing table.
         * 
         * \return a vector which contains all of the route entries.
         */
        std::vector<RouteEntry> route_entries();

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
        
        /**
         * \brief Converts mhz units to the appropriate channel number.
         * \param mhz The mhz units to be converted.
         * \return The channel number.
         */
        uint16_t mhz_to_channel(uint16_t mhz);
        
        /**
         * \brief Converts a PDUType to a string.
         * \param pduType The PDUType to be converted.
         * \return A string representation, for example "DOT11_QOS_DATA".
         */
        std::string to_string(PDU::PDUType pduType);

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
        
        /** \brief Performs the pseudo header checksum used in TCP and UDP PDUs.
         *
         * \param source_ip The source ip address.
         * \param dest_ip The destination ip address.
         * \param len The length to be included in the pseudo header.
         * \param flag The flag to use in the protocol field of the pseudo header.
         * \return The pseudo header checksum.
         */
        uint32_t pseudoheader_checksum(IPv6Address source_ip, IPv6Address dest_ip, uint32_t len, uint32_t flag);

        /** \brief Generic function to iterate through interface and collect
         * data.
         *
         * The parameter is applied to every interface found, allowing
         * the object to collect data from them.
         * \param functor An instance of an class which implements operator(struct ifaddrs*).
         */
        #ifndef WIN32
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
        #else // WIN32
        template<class Functor> 
        void generic_iface_loop(Functor &functor) {
            ULONG size;
            ::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
            std::vector<uint8_t> buffer(size);
            if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
                PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
                while(iface) {
                    if(functor(iface))
                        break;
                    iface = iface->Next;
                }
            }
        }
        #endif // WIN32
        
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
        inline PDU& dereference_until_pdu(PDU &pdu) {
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
        dereference_until_pdu(T &value) {
            return dereference_until_pdu(*value);
        }
        #if defined(BSD) || defined(__FreeBSD_kernel__)
        inline std::vector<char> query_route_table() {
            int mib[6];
            std::vector<char> buf;
            size_t len;

            mib[0] = CTL_NET;
            mib[1] = AF_ROUTE;
            mib[2] = 0;
            mib[3] = AF_INET;
            mib[4] = NET_RT_DUMP;
            mib[5] = 0;	
            if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
                throw std::runtime_error("sysctl failed");

            buf.resize(len);
            if (sysctl(mib, 6, &buf[0], &len, NULL, 0) < 0) {
                throw std::runtime_error("sysctl failed");
            }

            return buf;
        }

        template<typename ForwardIterator>
        void parse_header(struct rt_msghdr *rtm, ForwardIterator iter)
        {
            char *ptr = (char *)(rtm + 1);
            sockaddr *sa = 0;

            for (int i = 0; i < RTAX_MAX; i++) {
                if (rtm->rtm_addrs & (1 << i)) {
                    sa = (struct sockaddr *)ptr;
                    ptr += sa->sa_len;
                    if (sa->sa_family == 0)
                        sa = 0;
                } 
                *iter++ = sa;
            }
        }
        #endif
    }
}
#if defined(BSD) || defined(__FreeBSD_kernel__)
template<class ForwardIterator>
void Tins::Utils::route_entries(ForwardIterator output) {
    std::vector<char> buffer = query_route_table();
    char *next = &buffer[0], *end = &buffer[buffer.size()];
    rt_msghdr *rtm;
    std::vector<sockaddr*> sa(RTAX_MAX);
    char iface_name[IF_NAMESIZE];
    while(next < end) {
        rtm = (rt_msghdr*)next;
        parse_header(rtm, sa.begin());
        if (sa[RTAX_DST] && sa[RTAX_GATEWAY] && if_indextoname(rtm->rtm_index, iface_name)) {
            RouteEntry entry;
            entry.destination = IPv4Address(((struct sockaddr_in *)sa[RTAX_DST])->sin_addr.s_addr);
            entry.gateway = IPv4Address(((struct sockaddr_in *)sa[RTAX_GATEWAY])->sin_addr.s_addr);
            if(sa[RTAX_GENMASK])
                entry.mask = IPv4Address(((struct sockaddr_in *)sa[RTAX_GENMASK])->sin_addr.s_addr);
            else
                entry.mask = IPv4Address(uint32_t());
            entry.interface = iface_name;
            *output++ = entry;
        }
        next += rtm->rtm_msglen;
    }
}
#elif defined(WIN32)
template<class ForwardIterator>
void Tins::Utils::route_entries(ForwardIterator output) {
    MIB_IPFORWARDTABLE *table;
    ULONG size = 0;
    char iface_name[256];
    GetIpForwardTable(0, &size, 0);
    std::vector<uint8_t> buffer(size);
    table = (MIB_IPFORWARDTABLE*)&buffer[0];
    GetIpForwardTable(table, &size, 0);
    
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_IPFORWARDROW *row = &table->table[i];
        if(row->dwForwardType == MIB_IPROUTE_TYPE_INDIRECT) {
            RouteEntry entry;
            entry.interface = NetworkInterface::from_index(row->dwForwardIfIndex).name();
            entry.destination = IPv4Address(row->dwForwardDest);
            entry.mask = IPv4Address(row->dwForwardMask);
            entry.gateway = IPv4Address(row->dwForwardNextHop);
            *output++ = entry;
        }
    }
}
#else
template<class ForwardIterator>
void Tins::Utils::route_entries(ForwardIterator output) {
    using namespace Tins::Internals;
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
#endif

#endif // TINS_UTILS_H
