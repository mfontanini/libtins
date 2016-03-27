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

#include <stdexcept>
#include <vector>
#include <cstring>
#include "macros.h"
#include "utils.h"
#ifndef _WIN32
    #include <netinet/in.h>
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <ifaddrs.h>
        #include <net/if_dl.h>
        #include <sys/socket.h>
    #else
        #include <linux/if_packet.h>
    #endif
    #include <ifaddrs.h>
    #include <net/if.h>
#else
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #undef interface
#endif
#include "network_interface.h"
#include "endianness.h"
#include "exceptions.h"

using std::string;
using std::wstring;
using std::vector;
using std::set;
using std::copy;

/** \cond */
struct InterfaceInfoCollector {
    typedef Tins::NetworkInterface::Info info_type;
    info_type* info;
    int iface_id;
    const char* iface_name;
    bool found_hw;
    bool found_ip;

    InterfaceInfoCollector(info_type* res, int id, const char* if_name) 
    : info(res), iface_id(id), iface_name(if_name), found_hw(false), found_ip(false) { }
    
    #ifndef _WIN32
    bool operator() (const struct ifaddrs* addr) {
        using Tins::Endian::host_to_be;
        using Tins::IPv4Address;
        #if defined(BSD) || defined(__FreeBSD_kernel__)
            #define TINS_BROADCAST_ADDR(addr) (addr->ifa_dstaddr)
            const struct sockaddr_dl* addr_ptr = ((struct sockaddr_dl*)addr->ifa_addr);
            
            if (addr->ifa_addr->sa_family == AF_LINK && addr_ptr->sdl_index == iface_id) {
                info->hw_addr = (const uint8_t*)LLADDR(addr_ptr);
                found_hw = true;
                info->is_up = info->is_up || (addr->ifa_flags & IFF_UP);
            }
        #else
            #define TINS_BROADCAST_ADDR(addr) (addr->ifa_broadaddr)
            const struct sockaddr_ll* addr_ptr = ((struct sockaddr_ll*)addr->ifa_addr);
            
            if (!addr->ifa_addr) {
                return false;
            }
            if (addr->ifa_addr->sa_family == AF_PACKET && addr_ptr->sll_ifindex == iface_id) {
                info->hw_addr = addr_ptr->sll_addr;
                found_hw = true;
                info->is_up = info->is_up || (addr->ifa_flags & IFF_UP);
            }
        #endif
            else if (!std::strcmp(addr->ifa_name, iface_name)) {
                if (addr->ifa_addr->sa_family == AF_INET) {
                    info->ip_addr = IPv4Address(((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr);
                    info->netmask = IPv4Address(((struct sockaddr_in *)addr->ifa_netmask)->sin_addr.s_addr);
                    if ((addr->ifa_flags & (IFF_BROADCAST | IFF_POINTOPOINT))) {
                        info->bcast_addr = IPv4Address(
                            ((struct sockaddr_in *)TINS_BROADCAST_ADDR(addr))->sin_addr.s_addr);
                    }
                    else {
                        info->bcast_addr = 0;
                    }
                    found_ip = true;
                }
                else if (addr->ifa_addr->sa_family == AF_INET6) {
                    Tins::NetworkInterface::IPv6Prefix prefix;
                    prefix.address = ((struct sockaddr_in6 *)addr->ifa_addr)->sin6_addr.s6_addr;
                    Tins::IPv6Address mask = ((struct sockaddr_in6 *)addr->ifa_netmask)->sin6_addr.s6_addr;
                    prefix.prefix_length = 0;
                    for (Tins::IPv6Address::iterator iter = mask.begin(); iter != mask.end(); ++iter) {
                        if (*iter == 255) {
                            prefix.prefix_length += 8;
                        }
                        else {
                            uint8_t current_value = 128;
                            while (*iter > 0) {
                                prefix.prefix_length += 1;
                                *iter &= ~current_value;
                                current_value /= 2;
                            }
                            break;
                        }
                    }
                    info->ipv6_addrs.push_back(prefix);
                }
            }
        #undef TINS_BROADCAST_ADDR
        return found_ip && found_hw;
    }
    #else // _WIN32
    bool operator() (const IP_ADAPTER_ADDRESSES* iface) {
        using Tins::IPv4Address;
        using Tins::Endian::host_to_be;
        if (iface_id == uint32_t(iface->IfIndex)) {
            copy(iface->PhysicalAddress, iface->PhysicalAddress + 6, info->hw_addr.begin());
            found_hw = true;
            IP_ADAPTER_UNICAST_ADDRESS* unicast = iface->FirstUnicastAddress;
            while (unicast) {
                int family = ((const struct sockaddr*)unicast->Address.lpSockaddr)->sa_family;
                if (family == AF_INET) {
                    info->ip_addr = IPv4Address(((const struct sockaddr_in *)unicast->Address.lpSockaddr)->sin_addr.s_addr);
                    info->netmask = IPv4Address(host_to_be<uint32_t>(0xffffffff << (32 - unicast->OnLinkPrefixLength)));
                    info->bcast_addr = IPv4Address((info->ip_addr & info->netmask) | ~info->netmask);
                    info->is_up = (iface->Flags & IP_ADAPTER_IPV4_ENABLED) != 0;
                    found_ip = true;
                }
                else if (family == AF_INET6) {
                    Tins::NetworkInterface::IPv6Prefix prefix;
                    prefix.address = ((const struct sockaddr_in6 *)unicast->Address.lpSockaddr)->sin6_addr.s6_addr;
                    prefix.prefix_length = unicast->OnLinkPrefixLength;
                    info->ipv6_addrs.push_back(prefix);
                    found_ip = true;
                }
                unicast = unicast->Next;
            }
        }
        return found_ip && found_hw;
    }
    #endif // _WIN32
};

#ifdef _WIN32
template <typename T, typename U>
T find_adapter_address_info(uint32_t iface_id, U (IP_ADAPTER_ADDRESSES::*member)) {
    ULONG size;
    ::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
    vector<uint8_t> buffer(size);
    if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
        PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
        while (iface) {
            if (iface->IfIndex == iface_id) {
                return T(iface->*member);
            }
            iface = iface->Next;
        }
    }
    throw Tins::invalid_interface();
}
#endif // _WIN32

/** \endcond */

namespace Tins {

// static
NetworkInterface NetworkInterface::default_interface() {
    return NetworkInterface(IPv4Address(uint32_t(0)));
}

vector<NetworkInterface> NetworkInterface::all() {
    const set<string> interfaces = Utils::network_interfaces();
    vector<NetworkInterface> output;
    for (set<string>::const_iterator it = interfaces.begin(); it != interfaces.end(); ++it) {
        output.push_back(*it);
    }
    return output;
}
    
NetworkInterface::NetworkInterface()
: iface_id_(0) {

}

NetworkInterface NetworkInterface::from_index(id_type identifier) {
    NetworkInterface iface;
    iface.iface_id_ = identifier;
    return iface;
}

NetworkInterface::NetworkInterface(const char* name) {
    iface_id_ = name ? resolve_index(name) : 0;
}    

NetworkInterface::NetworkInterface(const std::string& name) {
    iface_id_ = resolve_index(name.c_str());
}

NetworkInterface::NetworkInterface(IPv4Address ip) 
: iface_id_(0) {
    typedef vector<Utils::RouteEntry> entries_type;
    
    if (ip == "127.0.0.1") {
        #if defined(BSD) || defined(__FreeBSD_kernel__)
        iface_id_ = resolve_index("lo0");
        #else
        iface_id_ = resolve_index("lo");
        #endif
    }
    else {
        const Utils::RouteEntry* best_match = 0;
        entries_type entries;
        uint32_t ip_int = ip;
        Utils::route_entries(std::back_inserter(entries));
        for (entries_type::const_iterator it(entries.begin()); it != entries.end(); ++it) {
            if ((ip_int & it->mask) == it->destination) {
                if (!best_match || it->mask > best_match->mask || it->metric < best_match->metric) {
                    best_match = &*it;
                }
            }
        }
        if (!best_match) {
            throw invalid_interface();
        }
        iface_id_ = resolve_index(best_match->interface.c_str());
    }
}

string NetworkInterface::name() const {
    #ifndef _WIN32
    char iface_name[IF_NAMESIZE];
    if (!if_indextoname(iface_id_, iface_name)) {
        throw invalid_interface();
    }
    return iface_name;
    #else // _WIN32
    return find_adapter_address_info<string>(iface_id_, &IP_ADAPTER_ADDRESSES::AdapterName);
    #endif // WIN32
}

wstring NetworkInterface::friendly_name() const {
    #ifndef _WIN32
    string n = name();
    return wstring(n.begin(), n.end());
    #else // _WIN32
    return find_adapter_address_info<wstring>(iface_id_, &IP_ADAPTER_ADDRESSES::FriendlyName);
    #endif // WIN32
}

NetworkInterface::Info NetworkInterface::addresses() const {
    return info();
}

NetworkInterface::Info NetworkInterface::info() const {
    const std::string& iface_name = name();
    Info info;
    InterfaceInfoCollector collector(&info, iface_id_, iface_name.c_str());
    info.is_up = false;

    #ifdef _WIN32

    ULONG size;
    ::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
    std::vector<uint8_t> buffer(size);
    if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
        PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
        while (iface) {
            collector(iface);
            iface = iface->Next;
        }
    }

    #else // _WIN32

    struct ifaddrs* ifaddrs = 0;
    struct ifaddrs* if_it = 0;
    getifaddrs(&ifaddrs);
    for (if_it = ifaddrs; if_it; if_it = if_it->ifa_next) {
        collector(if_it);
    }
    if (ifaddrs) {
        freeifaddrs(ifaddrs);
    }

    #endif // _WIN32
    
     // If we didn't even get the hw address or ip address, this went wrong
    if (!collector.found_hw && !collector.found_ip) {
        throw invalid_interface();
    }

    return info;
}

bool NetworkInterface::is_loopback() const {
    return info().ip_addr.is_loopback();
}

bool NetworkInterface::is_up() const {
    return info().is_up;
}

NetworkInterface::address_type NetworkInterface::hw_address() const {
    return info().hw_addr;
}

IPv4Address NetworkInterface::ipv4_address() const {
    return info().ip_addr;
}

IPv4Address NetworkInterface::ipv4_mask() const {
    return info().netmask;
}

IPv4Address NetworkInterface::ipv4_broadcast() const {
    return info().bcast_addr;
}

vector<NetworkInterface::IPv6Prefix> NetworkInterface::ipv6_addresses() const {
    return info().ipv6_addrs;
}

NetworkInterface::id_type NetworkInterface::resolve_index(const char* name) {
    #ifndef _WIN32
    id_type id = if_nametoindex(name);
    if (!id) {
        throw invalid_interface();
    }
    return id;
    #else // _WIN32
    ULONG size;
    ::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
    vector<uint8_t> buffer(size);
    if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
        PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
        while (iface) {
            if (strcmp(iface->AdapterName, name) == 0) {
                return iface->IfIndex;
            }
            iface = iface->Next;
        }
    }
    throw invalid_interface();
    #endif // _WIN32
}

} // Tins
