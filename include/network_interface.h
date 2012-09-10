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
 
#ifndef TINS_NETWORK_INTERFACE_H
#define TINS_NETWORK_INTERFACE_H

#include <string>
#include <stdint.h>
#include "hw_address.h"
#include "ip_address.h"

namespace Tins {
/**
 * \class NetworkInterface
 * \brief Abstraction of a network interface
 */
class NetworkInterface {
public:
    /**
     * \brief The type used to store the interface's identifier.
     */
    typedef uint32_t id_type;
    
    /**
     * \brief The type of this interface's address.
     */
    typedef HWAddress<6> address_type;
    
    /**
     * \brief Struct that holds an interface's addresses.
     */
    struct Info {
        IPv4Address ip_addr, netmask, bcast_addr;
        address_type hw_addr;
    };

    /**
     * Returns a NetworkInterface object associated with the default
     * interface.
     */
    static NetworkInterface default_interface();

    /**
     * Default constructor.
     */
    NetworkInterface(); 
    
    /**
     * \brief Constructor from std::string.
     * 
     * \param name The name of the interface this object will abstract.
     */
    NetworkInterface(const std::string &name);
    
    /**
     * \brief Constructor from const char*.
     * 
     * \param name The name of the interface this object will abstract.
     */
    NetworkInterface(const char *name);
    
    /**
     * \brief Constructs a NetworkInterface from an ip address.
     * 
     * This abstracted interface will be the one that would be the gateway
     * when sending a packet to the given ip.
     * 
     * \param ip The ip address being looked up.
     */
    NetworkInterface(IPv4Address ip);
    
    /**
     * \brief Getter for this interface's identifier.
     * 
     * \return id_type containing the identifier.
     */
    id_type id() const {
        return iface_id;
    }
    
    /**
     * \brief Retrieves this interface's name.
     * 
     * \return std::string containing this interface's name.
     */
    std::string name() const;
    
    /**
     * \brief Retrieve this interface's addresses.
     * 
     * This method iterates through all the interface's until the 
     * correct one is found. Therefore it's O(N), being N the amount
     * of interfaces in the system.
     */
    Info addresses() const;
    
    /**
     * \brief Tests whether this is a valid interface;
     * 
     * An interface will not be valid iff it was created using the
     * default constructor. 
     */
    operator bool() const {
        return iface_id != 0;
    }
    
    /**
     * \brief Compares this interface for equality.
     * 
     * \param rhs The interface being compared.
     */
    bool operator==(const NetworkInterface &rhs) const {
        return iface_id == rhs.iface_id;
    }
    
    /**
     * \brief Compares this interface for inequality.
     * 
     * \param rhs The interface being compared.
     */
    bool operator!=(const NetworkInterface &rhs) const {
        return !(*this == rhs);
    }
private:
    id_type resolve_index(const char *name);

    id_type iface_id;
};
}
#endif // TINS_NETWORK_INTERFACE_H
