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
 
#ifndef TINS_NETWORK_INTERFACE_H
#define TINS_NETWORK_INTERFACE_H

#include <string>
#include <vector>
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
     * Returns all available network interfaces.
     */
    static std::vector<NetworkInterface> all();

    /**
     * Returns a network interface for the given index.
     */
    static NetworkInterface from_index(id_type identifier);

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
     * This name can be used as the interface name provided to the
     * Sniffer class when starting a sniffing session.
     *
     * \sa Sniffer
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
