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

#ifndef TINS_PPI_H
#define TINS_PPI_H

#include "pdu.h"
#include "endianness.h"
#include "small_uint.h"

namespace Tins {
/**
 * \class PPI
 * \brief Represents a Per-Packet Information PDU.
 *
 * This PDU can only be constructed from a buffer, and
 * cannot be serialized. Therefore, it is only useful while
 * sniffing packets.
 */
class PPI : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::PPI;

    /**
     * \brief Constructs an PPI object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this 
     * one.
     * 
     * If there is not enough size for an PPI header, a 
     * malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    PPI(const uint8_t *buffer, uint32_t total_sz);

    // Getters

    /**
     *  \brief Getter for the version field.
     *  \return The stored version field value.
     */
    uint8_t version() const {
        return _header.version;
    }

    /**
     *  \brief Getter for the flags field.
     *  \return The stored flags field value.
     */
    uint8_t flags() const {
        return _header.flags;
    }

    /**
     *  \brief Getter for the length field.
     *  \return The stored length field value.
     */
    uint16_t length() const {
        return Endian::le_to_host(_header.length);
    }

    /**
     *  \brief Getter for the Data Link Type field.
     *  \return The stored Data Link Type field value.
     */
    uint32_t dlt() const {
        return Endian::le_to_host(_header.dlt);
    }

    /**
     * \brief Returns the header size.
     *
     * This metod overrides PDU::header_size. \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    PPI *clone() const {
        return new PPI(*this);
    }
private:
    void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *);

    struct header {
        uint8_t version, flags;
        uint16_t length;
        uint32_t dlt;
    };

    header _header;
    byte_array _data;
};
}

#endif // TINS_PPI_H
