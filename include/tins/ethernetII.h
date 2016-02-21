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

#ifndef TINS_ETHERNET_II_H
#define TINS_ETHERNET_II_H

#include <stdint.h>
#include "macros.h"
#include "pdu.h"
#include "config.h"
#include "endianness.h"
#include "hw_address.h"

namespace Tins {

/**
 * \class EthernetII
 * \brief Represents an Ethernet II PDU.
 */
class TINS_API EthernetII : public PDU {
public:
    /**
     * \brief The hardware address type.
     */
    typedef HWAddress<6> address_type;
    
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::ETHERNET_II;

    /**
     * \brief Represents the ethernetII broadcast address.
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
     * \brief Constructs an ethernet II PDU.
     *
     * \param dst_hw_addr address_type containing the destination's MAC.
     * \param src_hw_addr address_type containing the source's MAC.
     */
    EthernetII(const address_type& dst_hw_addr = address_type(), 
               const address_type& src_hw_addr = address_type());

    /**
     * \brief Constructs a EthernetII object from a buffer and adds 
     * all identifiable PDUs found in the buffer as children of 
     * this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for a EthernetII header in the 
     * buffer, a malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    EthernetII(const uint8_t* buffer, uint32_t total_sz);

    /* Getters */
    /**
     * \brief Getter for the destination's hardware address.
     *
     * \return address_type containing the destination hardware 
     * address.
     */
    address_type dst_addr() const {
        return header_.dst_mac;
    }

    /**
     * \brief Getter for the source's hardware address.
     *
     * \return address_type containing the source hardware address.
     */
    address_type src_addr() const {
        return header_.src_mac;
    }

    /**
     * \brief Getter for the payload_type
     * \return The payload type.
     */
    uint16_t payload_type() const {
        return Endian::be_to_host(header_.payload_type);
    }

    /* Setters */

    /**
     * \brief Setter for the destination hardware address.
     *
     * \param new_dst_addr the destination hardware address to be set.
     */
    void dst_addr(const address_type& new_dst_addr);

    /**
     * \brief Setter for the source hardware address.
     *
     * \param new_src_addr the source hardware address to be set.
     */
    void src_addr(const address_type& new_src_addr);

    /**
     * \brief Setter for the payload type.
     *
     * \param new_payload_type the new value of the payload type field.
     */
    void payload_type(uint16_t new_payload_type);

    /* Virtual methods */
    /**
     * \brief Returns the ethernet frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;
    
    /**
     * \brief Returns the ethernet II frame's padding.
     *
     * \return An uint32_t with the padding size.
     * \sa PDU::trailer_size()
     */
    uint32_t trailer_size() const;

    /**
     * \sa PDU::send()
     */
    void send(PacketSender& sender, const NetworkInterface& iface);

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
     * \brief Receives a matching response for this packet.
     *
     * \sa PDU::recv_response
     */
    PDU* recv_response(PacketSender& sender, const NetworkInterface& iface);
    #endif // _WIN32

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \sa PDU::clone
     */
    EthernetII* clone() const {
        return new EthernetII(*this);
    }
private:
    /**
     * Struct that represents the Ethernet II header
     */
    TINS_BEGIN_PACK
    struct ethernet_header {
        uint8_t dst_mac[address_type::address_size];
        uint8_t src_mac[address_type::address_size];
        uint16_t payload_type;
    } TINS_END_PACK;
    
    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent);

    ethernet_header header_;
};

} // Tins

#endif // TINS_ETHERNET_II_H
