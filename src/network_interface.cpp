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

#include <stdexcept>
#include <vector>
#include <cstring>
#include "macros.h"
#ifndef WIN32
    #include <netinet/in.h>
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <ifaddrs.h>
        #include <net/if_dl.h>
        #include <sys/socket.h>
    #else
        #include <linux/if_packet.h>
    #endif
    #include <net/if.h>
#else
    #include <winsock2.h>
    #include <Iphlpapi.h>
#endif
#include "network_interface.h"
#include "utils.h"
#include "endianness.h"

using std::string;
using std::vector;
using std::set;

/** \cond */
struct InterfaceInfoCollector {
    typedef Tins::NetworkInterface::Info info_type;
    info_type *info;
    int iface_id;
    const char* iface_name;
    bool found;

    InterfaceInfoCollector(info_type *res, int id, const char* if_name) 
    : info(res), iface_id(id), iface_name(if_name), found(false) { }
    
    #ifndef WIN32
    bool operator() (const struct ifaddrs *addr) {
        using Tins::Endian::host_to_be;
            using Tins::IPv4Address;
        #if defined(BSD) || defined(__FreeBSD_kernel__)
            const struct sockaddr_dl* addr_ptr = ((struct sockaddr_dl*)addr->ifa_addr);
            
            if(addr->ifa_addr->sa_family == AF_LINK && addr_ptr->sdl_index == iface_id)
                info->hw_addr = (const uint8_t*)LLADDR(addr_ptr); // mmmm
            else if(addr->ifa_addr->sa_family == AF_INET && !std::strcmp(addr->ifa_name, iface_name)) {
                info->ip_addr = IPv4Address(((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr);
                info->netmask = IPv4Address(((struct sockaddr_in *)addr->ifa_netmask)->sin_addr.s_addr);
                if((addr->ifa_flags & (IFF_BROADCAST | IFF_POINTOPOINT)))
                    info->bcast_addr = IPv4Address(((struct sockaddr_in *)addr->ifa_dstaddr)->sin_addr.s_addr);
                else
                    info->bcast_addr = 0;
                found = true;
            }
            return found;
        #else
            const struct sockaddr_ll* addr_ptr = ((struct sockaddr_ll*)addr->ifa_addr);
            
            if(addr->ifa_addr) {
                if(addr->ifa_addr->sa_family == AF_PACKET && addr_ptr->sll_ifindex == iface_id)
                    info->hw_addr = addr_ptr->sll_addr;
                else if(addr->ifa_addr->sa_family == AF_INET && !std::strcmp(addr->ifa_name, iface_name)) {
                    info->ip_addr = IPv4Address(((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr);
                    info->netmask = IPv4Address(((struct sockaddr_in *)addr->ifa_netmask)->sin_addr.s_addr);
                    if((addr->ifa_flags & (IFF_BROADCAST | IFF_POINTOPOINT)))
                        info->bcast_addr = IPv4Address(((struct sockaddr_in *)addr->ifa_ifu.ifu_broadaddr)->sin_addr.s_addr);
                    else
                        info->bcast_addr = 0;
                    found = true;
                }
            }
            return found;
        #endif
    }
    #else // WIN32
    bool operator() (const IP_ADAPTER_ADDRESSES *iface) {
        using Tins::IPv4Address;
        using Tins::Endian::host_to_be;
        if(iface_id == uint32_t(iface->IfIndex)) {
            std::copy(iface->PhysicalAddress, iface->PhysicalAddress + 6, info->hw_addr.begin());
            const IP_ADAPTER_UNICAST_ADDRESS *unicast = iface->FirstUnicastAddress;
            if(unicast) {
                info->ip_addr = IPv4Address(((const struct sockaddr_in *)unicast->Address.lpSockaddr)->sin_addr.s_addr);
                info->netmask = IPv4Address(host_to_be<uint32_t>(0xffffffff << (32 - unicast->OnLinkPrefixLength)));
                info->bcast_addr = IPv4Address((info->ip_addr & info->netmask) | ~info->netmask);
                found = true;
            }
        }
        return found;
    }
    #endif // WIN32
};
/** \endcond */

namespace Tins {
// static
NetworkInterface NetworkInterface::default_interface() {
    return NetworkInterface(IPv4Address(uint32_t(0)));
}

vector<NetworkInterface> NetworkInterface::all() {
    const set<string> interfaces = Utils::network_interfaces();
    vector<NetworkInterface> output;
    for(set<string>::const_iterator it = interfaces.begin(); it != interfaces.end(); ++it) {
        output.push_back(*it);
    }
    return output;
}
    
NetworkInterface::NetworkInterface() : iface_id(0) {

}

NetworkInterface NetworkInterface::from_index(id_type identifier) {
    NetworkInterface iface;
    iface.iface_id = identifier;
    return iface;
}

NetworkInterface::NetworkInterface(const char *name) {
    iface_id = name ? resolve_index(name) : 0;
}    

NetworkInterface::NetworkInterface(const std::string &name) {
    iface_id = resolve_index(name.c_str());
}

NetworkInterface::NetworkInterface(IPv4Address ip) : iface_id(0) {
    typedef std::vector<Utils::RouteEntry> entries_type;
    
    if(ip == "127.0.0.1")
        #if defined(BSD) || defined(__FreeBSD_kernel__)
        iface_id = resolve_index("lo0");
        #else
        iface_id = resolve_index("lo");
        #endif
    else {
        const Utils::RouteEntry *best_match = 0;
        entries_type entries;
        uint32_t ip_int = ip;
        Utils::route_entries(std::back_inserter(entries));
        for(entries_type::const_iterator it(entries.begin()); it != entries.end(); ++it) {
            if((ip_int & it->mask) == it->destination) {
                if(!best_match || it->mask > best_match->mask) {
                    best_match = &*it;
                }
            }
        }
        if(!best_match)
            throw std::runtime_error("Error looking up interface");
        iface_id = resolve_index(best_match->interface.c_str());
    }
}

std::string NetworkInterface::name() const {
    #ifndef WIN32
    char iface_name[IF_NAMESIZE];
    if(!if_indextoname(iface_id, iface_name))
        throw std::runtime_error("Error fetching this interface's name");
    return iface_name;
    #else // WIN32
    ULONG size;
    ::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
    std::vector<uint8_t> buffer(size);
    if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
        PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
        while (iface) {
            if (iface->IfIndex == iface_id) {
                return iface->AdapterName;
            }
            iface = iface->Next;
        }
    }
    throw std::runtime_error("Failed to find interface name");
    #endif // WIN32
}

NetworkInterface::Info NetworkInterface::addresses() const {
    const std::string &iface_name = name();
    Info info;
    InterfaceInfoCollector collector(&info, iface_id, iface_name.c_str());
    Utils::generic_iface_loop(collector);
    if(!collector.found)
        throw std::runtime_error("Error looking up interface address");
    return info;
}

NetworkInterface::id_type NetworkInterface::resolve_index(const char *name) {
    #ifndef WIN32
    id_type id = if_nametoindex(name);
    if(!id)
        throw std::runtime_error("Invalid interface");
    return id;
    #else // Win32
    ULONG size;
    ::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
    std::vector<uint8_t> buffer(size);
    if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
        PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
        while (iface) {
            if (strcmp(iface->AdapterName, name) == 0) {
                return iface->IfIndex;
            }
            iface = iface->Next;
        }
    }
    throw std::runtime_error("Invalid interface");
    #endif // Win32
}
}

