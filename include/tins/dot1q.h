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

#ifndef TINS_DOT1Q_H
#define TINS_DOT1Q_H

#include <tins/pdu.h>
#include <tins/macros.h>
#include <tins/endianness.h>
#include <tins/small_uint.h>

namespace Tins {

/**
 * \class Dot1Q
 * Represents an IEEE 802.1q PDU.
 */
class TINS_API Dot1Q : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT1Q;
    
    /**
     * \brief Extracts metadata for this protocol based on the buffer provided
     *
     * \param buffer Pointer to a buffer
     * \param total_sz Size of the buffer pointed by buffer
     */
    static metadata extract_metadata(const uint8_t *buffer, uint32_t total_sz);

    /**
     * Default constructor
     */
    Dot1Q(small_uint<12> tag_id = 0, bool append_pad = true);

    /**
     * \brief Constructs a Dot1Q object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this 
     * one. 
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for a Dot1Q header in the buffer,
     * a malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot1Q(const uint8_t* buffer, uint32_t total_sz);

    // Getters

    /**
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Returns the frame's trailer size.
     * \return The trailer's size.
     */
    uint32_t trailer_size() const;

    /**
     * \brief Getter for the priority field.
     * \return The stored priority field value.
     */
    small_uint<3> priority() const {
        return header_.priority;
    }

    /**
     * \brief Getter for the Canonical Format Identifier field.
     * \return The stored CFI field value.
     */
    small_uint<1> cfi() const {
        return header_.cfi;
    }

    /**
     * \brief Getter for the VLAN ID field.
     * \return The stored VLAN ID field value.
     */
    small_uint<12> id() const {
        #if TINS_IS_LITTLE_ENDIAN
            return header_.idL | (header_.idH << 8);
        #else
            return header_.id;
        #endif
    }

    /**
     * \brief Getter for the payload type field.
     * \return The stored type field value.
     */
    uint16_t payload_type() const {
        return Endian::be_to_host(header_.type);
    }

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
    Dot1Q* clone() const {
        return new Dot1Q(*this);
    }

    /**
     * \brief Retrieves the flag indicating whether padding will be
     * appended at the end of this packet.
     */
    bool append_padding() const {
        return append_padding_;
    }

    // Setters

    /**
     * \brief Setter for the priority field.
     * \param new_priority The new priority field value.
     */
    void priority(small_uint<3> new_priority);

    /**
     * \brief Setter for the Canonical Format Identifie field.
     * \param new_cfi The new CFI field value.
     */
    void cfi(small_uint<1> new_cfi);

    /**
     * \brief Setter for the VLAN ID field.
     * \param new_id The new VLAN ID field value.
     */
    void id(small_uint<12> new_id);

    /**
     * \brief Setter for the payload type field.
     * \param new_type The new type field value.
     */
    void payload_type(uint16_t new_type);
    
    /**
     * \brief Indicates whether the appropriate padding will be 
     * at the end of the packet.
     * 
     * This flag could be disabled in case two or more contiguous Dot1Q 
     * PDUs are added to a packet. In that case, only the Dot1Q which is 
     * closer to the link layer should add the padding at the end.
     * 
     * \param value A boolean indicating whether padding will be appended.
     */
    void append_padding(bool value);
    
    /** 
     * \brief Check whether ptr points to a valid response for this PDU.
     *
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const;
private:
    void write_serialization(uint8_t* buffer, uint32_t total_sz);

    TINS_BEGIN_PACK
    struct dot1q_header {
        #if TINS_IS_BIG_ENDIAN
            uint16_t priority:3,
                    cfi:1,
                    id:12;
            uint16_t type;
        #else
            uint16_t idH:4,
                    cfi:1,
                    priority:3,
                    idL:8;
            uint16_t type;
        #endif
    } TINS_END_PACK;
    
    static uint16_t get_id(const dot1q_header* hdr);
    
    dot1q_header header_;
    bool append_padding_;
};
}

#endif // TINS_DOT1Q_H
