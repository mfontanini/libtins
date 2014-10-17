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

#ifndef TINS_SLL_H
#define TINS_SLL_H

#include <vector>
#include "pdu.h"
#include "endianness.h"
#include "hw_address.h"

namespace Tins {
/**
 * \class SLL
 * \brief Represents a Linux cooked-mode capture (SLL) PDU.
 */
class SLL : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::SLL;

    /**
     *  The type of the address type
     */
    typedef HWAddress<8> address_type;
    
    /**
     * Default constructor
     */
    SLL();
    
    /**
     * \brief Constructs a SLL object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for a SLL header in the 
     * buffer, a malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    SLL(const uint8_t *buffer, uint32_t total_sz);
    
    // Getters

    /**
     *  \brief Getter for the Packet Type field.
     *  \return The stored Packet Type field value.
     */
    uint16_t packet_type() const {
        return Endian::be_to_host(_header.packet_type);
    }

    /**
     *  \brief Getter for the LLADDR Type field.
     *  \return The stored LLADDR Type field value.
     */
    uint16_t lladdr_type() const {
        return Endian::be_to_host(_header.lladdr_type);
    }

    /**
     *  \brief Getter for the LLADDR Length field.
     *  \return The stored LLADDR Length field value.
     */
    uint16_t lladdr_len() const {
        return Endian::be_to_host(_header.lladdr_len);
    }

    /**
     *  \brief Getter for the Address field.
     *  \return The stored Address field value.
     */
    address_type address() const {
        return _header.address;
    }

    /**
     *  \brief Getter for the Protocol field.
     *  \return The stored Protocol field value.
     */
    uint16_t protocol() const {
        return Endian::be_to_host(_header.protocol);
    }
    
    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }
    
    // Setters

    /**
     *  \brief Setter for the Packet Type field.
     *  \param new_packet_type The new Packet Type field value.
     */
    void packet_type(uint16_t new_packet_type);

    /**
     *  \brief Setter for the LLADDR Type field.
     *  \param new_lladdr_type The new LLADDR Type field value.
     */
    void lladdr_type(uint16_t new_lladdr_type);

    /**
     *  \brief Setter for the LLADDR Length field.
     *  \param new_lladdr_len The new LLADDR Length field value.
     */
    void lladdr_len(uint16_t new_lladdr_len);

    /**
     *  \brief Setter for the Address field.
     *  \param new_address The new Address field value.
     */
    void address(const address_type &new_address);

    /**
     *  \brief Setter for the Protocol field.
     *  \param new_protocol The new Protocol field value.
     */
    void protocol(uint16_t new_protocol);
    
    /**
     * \brief Returns the header size.
     *
     * This metod overrides PDU::header_size. \sa PDU::header_size
     */
    uint32_t header_size() const;
    
    /**
     * \sa PDU::clone
     */
    SLL *clone() const {
        return new SLL(*this);
    }
private:
    TINS_BEGIN_PACK
    struct sllhdr {
        uint16_t packet_type, lladdr_type, lladdr_len;
        uint8_t address[8];
        uint16_t protocol;
    } TINS_END_PACK;
    
    void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *);
    
    sllhdr _header;
};
}

#endif // TINS_SLL_H
