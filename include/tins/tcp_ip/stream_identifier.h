/*
 * Copyright (c) 2017, Matias Fontanini
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

#ifndef TINS_TCP_IP_STREAM_ID_H
#define TINS_TCP_IP_STREAM_ID_H

#include <tins/config.h>

#ifdef TINS_HAVE_TCPIP

#include <array>
#include <stdint.h>

namespace Tins {

class PDU;
class IPv4Address;
class IPv6Address;

namespace TCPIP {

class Stream;

/**
 * \brief Uniquely identifies a stream. 
 *
 * This struct is used to track TCP/UDP streams. It keeps track of minimum and maximum
 * addresses/ports in a stream to match packets coming from any of the 2 endpoints
 * into the same object.
 *
 * This struct implements operator< so it can be used as a key on std::maps
 */
struct StreamIdentifier {
    /**
     * The type used to store each endpoint's address
     */
    typedef std::array<uint8_t, 16> address_type;

    /**
     * Default constructor
     */
    StreamIdentifier();

    /**
     * Constructs a StreamIdentifier
     *
     * \param client_addr Client's address
     * \param client_port Port's port
     * \param server_addr Server's address
     * \param server_port Server's port
     */
    StreamIdentifier(const address_type& client_addr, uint16_t client_port,
                     const address_type& server_addr, uint16_t server_port);

    /**
     * Indicates whether this stream identifier is lower than rhs
     */
    bool operator<(const StreamIdentifier& rhs) const;

    /**
     * Compares this stream identifier for equality
     */ 
    bool operator==(const StreamIdentifier& rhs) const;

    address_type min_address;
    address_type max_address;
    uint16_t min_address_port;
    uint16_t max_address_port;

    static StreamIdentifier make_identifier(const PDU& packet);
    static StreamIdentifier make_identifier(const Stream& stream);
    static address_type serialize(IPv4Address address);
    static address_type serialize(const IPv6Address& address);
};

} // TCPIP
} // Tins

#endif // TINS_HAVE_TCPIP
#endif // TINS_TCP_IP_STREAM_ID_H

