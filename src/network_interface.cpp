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
#ifndef WIN32
    #include <linux/if_packet.h>
    #include <net/if.h>
#endif
#include "network_interface.h"
#include "utils.h"

/** \cond */
template<typename Address>
struct HWAddressCollector {
    Address *result;
    int iface_id;
    bool found;

    HWAddressCollector(Tins::HWAddress<6> *res, int id) 
    : result(res), iface_id(id), found(false){ }

    bool operator() (struct ifaddrs *addr) {
        const struct sockaddr_ll* addr_ptr = ((struct sockaddr_ll*)addr->ifa_addr);
        if(!found && addr->ifa_addr->sa_family == AF_PACKET && addr_ptr->sll_ifindex == iface_id) {
            *result = addr_ptr->sll_addr;
            found = true;
        }
        return found;
    }
};

namespace Tins {
NetworkInterface::NetworkInterface(const std::string &name) {
    iface_id = if_nametoindex(name.c_str());
    if(!iface_id)
        throw std::runtime_error("Invalid interface error");
}

NetworkInterface::NetworkInterface(id_type id) 
: iface_id(id) {
    
}

NetworkInterface::address_type NetworkInterface::address() {
    address_type addr;
    ::HWAddressCollector<address_type> collector(&addr, iface_id);
    Utils::generic_iface_loop(collector);
    if(!collector.found)
        throw std::runtime_error("Error looking up interface address");
    return addr;
}
}

