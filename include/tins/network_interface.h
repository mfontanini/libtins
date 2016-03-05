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
 
#ifndef TINS_NETWORK_INTERFACE_H
#define TINS_NETWORK_INTERFACE_H

#include <string>
#include <vector>
#include <stdint.h>
#include "macros.h"
#include "hw_address.h"
#include "ip_address.h"
#include "ipv6_address.h"

namespace Tins {

/**
 * \class NetworkInterface
 * \brief Abstraction of a network interface
 */
class TINS_API NetworkInterface {
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
     *
     */
    struct IPv6Prefix {
        IPv6Address address;
        uint32_t prefix_length;
    };

    /**
     * \brief Struct that holds an interface's addresses.
     */
    struct Info {
        IPv4Address ip_addr, netmask, bcast_addr;
        std::vector<IPv6Prefix> ipv6_addrs;
        address_type hw_addr;
        bool is_up;
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
    NetworkInterface(const std::string& name);
    
    /**
     * \brief Constructor from const char*.
     * 
     * \param name The name of the interface this object will abstract.
     */
    NetworkInterface(const char* name);
    
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
        return iface_id_;
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
     * \brief Retrieves this interface's friendly name.
     *
     * The name returned by this method can be more human-friendly than
     * the one returned by NetworkInterface::name, depending on the platform
     * in which it's used. 
     *
     * On GNU/Linux and OSX/FreeBSD, this returns the same string as 
     * NetworkInterface::name.
     *
     * On Windows, this method returns a name such as 
     * "Local Area Connection 1".
     *
     * Note thaat this returns a wstring rather than a string, to comply
     * with Window's adapter's FriendlyName type.
     *
     * \return std::wstring containing this interface's name.
     */
    std::wstring friendly_name() const;
    
    /**
     * \brief Retrieve this interface's addresses.
     * 
     * This method is deprecated. You should use NetworkInterface::info (this
     * is just a naming deprecation, NetworkInterface::info is equivalent).
     * \deprecated
     */
    Info addresses() const;

    /**
     * \brief Retrieve this interface's information.
     * 
     * This method iterates through all the interface's until the 
     * correct one is found. Therefore it's O(N), being N the amount
     * of interfaces in the system.
     */
    Info info() const;
    
    /**
     * \brief Tests whether this is a valid interface;
     * 
     * An interface will not be valid iff it was created using the
     * default constructor. 
     */
    operator bool() const {
        return iface_id_ != 0;
    }

    /**
     * \brief Indicates whether this is a loopback device.
     * @return true iff this is a loopback device.
     */
    bool is_loopback() const;

    /**
     * \brief Indicates whether this interface is up.
     *
     * This is equivalent to getting the interface info and checking for the is_up 
     * attribute.
     */
    bool is_up() const;

    /**
     * \brief Retrieves the hardware address for this interface.
     */
    address_type hw_address() const;

    /**
     * \brief Retrieves the IPv4 address for this interface.
     */
    IPv4Address ipv4_address() const;

    /**
     * \brief Retrieves the IPv4 netmask for this interface.
     */
    IPv4Address ipv4_mask() const;

    /**
     * \brief Retrieves the broadcast IPv4 address for this interface.
     */
    IPv4Address ipv4_broadcast() const;

    /**
     * \brief Retrieves the IPv6 addresses for this interface.
     */
    std::vector<IPv6Prefix> ipv6_addresses() const;

    /**
     * \brief Compares this interface for equality.
     * 
     * \param rhs The interface being compared.
     */
    bool operator==(const NetworkInterface& rhs) const {
        return iface_id_ == rhs.iface_id_;
    }
    
    /**
     * \brief Compares this interface for inequality.
     * 
     * \param rhs The interface being compared.
     */
    bool operator!=(const NetworkInterface& rhs) const {
        return !(*this == rhs);
    }
private:
    id_type resolve_index(const char* name);

    id_type iface_id_;
};

} // Tins

#endif // TINS_NETWORK_INTERFACE_H
