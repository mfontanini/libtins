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

#ifndef TINS_DOT3_H
#define TINS_DOT3_H

#include <stdint.h>
#include "macros.h"
#include "pdu.h"
#include "config.h"
#include "endianness.h"
#include "hw_address.h"

namespace Tins {

/** 
 * \class Dot3
 * \brief Class representing an IEEE 802.3 PDU.
 */
class TINS_API Dot3 : public PDU {
public:
    /**
     * \brief The address type.
     */
    typedef HWAddress<6> address_type; 
    
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::IEEE802_3;

    /**
     * \brief Represents the Dot3 broadcast address.
     */
    static const address_type BROADCAST;

    /**
     * \brief Extracts metadata for this protocol based on the buffer provided
     *
     * \param buffer Pointer to a buffer
     * \param total_sz Size of the buffer pointed by buffer
     */
    static metadata extract_metadata(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Constructor for creating an Dot3 PDU
     *
     * Constructor that builds an Dot3 PDU taking the interface name,
     * destination's and source's MAC.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     * \param child The PDU which will be set as the inner PDU.
     */
    Dot3(const address_type& dst_hw_addr = address_type(), 
         const address_type& src_hw_addr = address_type());

    /**
     * \brief Constructs a Dot3 object from a buffer and adds a
     * LLC object with the remaining data as the inner PDU.
     * 
     * If there is not enough size for a Dot3 header, a 
     * malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot3(const uint8_t* buffer, uint32_t total_sz);

    /* Getters */
    /**
     * \brief Getter for the destination hardware address.
     *
     * \return The destination hardware address.
     */
    address_type dst_addr() const {
        return header_.dst_mac;
    }

    /**
     * \brief Getter for the source hardware address.
     *
     * \return The source hardware address.
     */
    address_type src_addr() const {
        return header_.src_mac;
    }

    /**
     * \brief Getter for the length field.
     * \return The length field value.
     */
    uint16_t length() const {
        return Endian::be_to_host(header_.length);
    }

    /* Setters */

    /**
     * \brief Setter for the destination hardware address.
     *
     * \param address The new destination hardware address.
     */
    void dst_addr(const address_type& address);

    /**
     * \brief Setter for the source hardware address.
     *
     * \param address The new source hardware address.
     */
    void src_addr(const address_type& address);

    /**
     * \brief Setter for the length field.
     *
     * \param value The new value for the length field
     */
    void length(uint16_t value);

    // Virtual methods

    /**
     * \brief Returns the Dot3 frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;
    
    #if !defined(_WIN32) || defined(TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET)
    /**
     * \sa PDU::send()
     */
    void send(PacketSender& sender, const NetworkInterface& iface);
    #endif // !_WIN32 || TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET

    /** 
     * \brief Check whether ptr points to a valid response for this PDU.
     *
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const;

    #ifndef _WIN32
    /** 
     * \sa PDU::recv_response
     */
    PDU* recv_response(PacketSender& sender, const NetworkInterface& iface);
    #endif // _WIN32

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \sa PDU::clone
     */
    Dot3* clone() const {
        return new Dot3(*this);
    }
private:
    /**
     * Struct that represents the Ethernet II header
     */
    TINS_BEGIN_PACK
    struct dot3_header {
        uint8_t dst_mac[address_type::address_size];
        uint8_t src_mac[address_type::address_size];
        uint16_t length;
    } TINS_END_PACK;

    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent);

    dot3_header header_;
};

} // Tins

#endif // TINS_DOT3_H
