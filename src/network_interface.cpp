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

#include <stdexcept>
#include <cstring>
#include <vector>
#ifndef WIN32
    #include <linux/if_packet.h>
    #include <net/if.h>
#endif
#include "network_interface.h"
#include "utils.h"

/** \cond */
struct InterfaceInfoCollector {
    typedef Tins::NetworkInterface::Info info_type;
    info_type *info;
    int iface_id;
    const char* iface_name;
    bool found;

    InterfaceInfoCollector(info_type *res, int id, const char* if_name) 
    : info(res), iface_id(id), iface_name(if_name), found(false) { }

    bool operator() (struct ifaddrs *addr) {
        using Tins::Utils::net_to_host_l;
        const struct sockaddr_ll* addr_ptr = ((struct sockaddr_ll*)addr->ifa_addr);
        
        if(addr->ifa_addr->sa_family == AF_PACKET && addr_ptr->sll_ifindex == iface_id)
            info->hw_addr = addr_ptr->sll_addr;
        else if(addr->ifa_addr->sa_family == AF_INET && !std::strcmp(addr->ifa_name, iface_name)) {
            info->ip_addr = net_to_host_l(((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr);
            info->netmask = net_to_host_l(((struct sockaddr_in *)addr->ifa_netmask)->sin_addr.s_addr);
            if((addr->ifa_flags & (IFF_BROADCAST | IFF_POINTOPOINT)))
                info->bcast_addr = net_to_host_l(((struct sockaddr_in *)addr->ifa_ifu.ifu_broadaddr)->sin_addr.s_addr);
            else
                info->bcast_addr = 0;
            found = true;
        }
        return found;
    }
};
/** \endcond */

namespace Tins {
NetworkInterface::NetworkInterface(const std::string &name) {
    iface_id = if_nametoindex(name.c_str());
    if(!iface_id)
        throw std::runtime_error("Invalid interface error");
}

NetworkInterface::NetworkInterface(IPv4Address ip) : iface_id(0) {
    typedef std::vector<Utils::RouteEntry> entries_type;
    
    if(ip == "127.0.0.1")
        iface_id = if_nametoindex("lo");
    else {
        entries_type entries;
        uint32_t ip_int = ip;
        route_entries(std::back_inserter(entries));
        for(entries_type::const_iterator it(entries.begin()); it != entries.end(); ++it) {
            if((ip_int & it->mask) == it->destination) {
                iface_id = if_nametoindex(it->interface.c_str());
                break;
            }
        }
        if(!iface_id)
            throw std::runtime_error("Error looking up interface");
    }
}

std::string NetworkInterface::name() const {
    char iface_name[IF_NAMESIZE];
    if(!if_indextoname(iface_id, iface_name))
        throw std::runtime_error("Error fetching this interface's name");
    return iface_name;
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
}

