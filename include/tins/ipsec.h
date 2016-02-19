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

#ifndef TINS_IPSEC_H
#define TINS_IPSEC_H

#include "pdu.h"
#include "macros.h"
#include "endianness.h"
#include "small_uint.h"

namespace Tins {

/**
 * \class IPSecAH
 * \brief Represents an IPSec Authentication Header.
 */
class TINS_API IPSecAH : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::IPSEC_AH;

    /**
     * \brief Default constructor.
     *
     * The ICV field is initialized with four 0 bytes. The length
     * field is initialized appropriately.
     */
    IPSecAH();
    
    /**
     * \brief Constructs an IPSecAH object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this 
     * one.
     * 
     * If there is not enough size for an IPSecAH header, a 
     * malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    IPSecAH(const uint8_t* buffer, uint32_t total_sz);

    // Getters

    /**
     *  \brief Getter for the Next header field.
     *  \return The stored Next header field value.
     */
    uint8_t next_header() const {
        return header_.next_header;
    }

    /**
     *  \brief Getter for the Length field.
     *  \return The stored Length field value.
     */
    uint8_t length() const {
        return header_.length;
    }

    /**
     *  \brief Getter for the Security Parameters Index field.
     *  \return The stored Security Parameters Index field value.
     */
    uint32_t spi() const {
        return Endian::be_to_host(header_.spi);
    }

    /**
     *  \brief Getter for the Sequence number field.
     *  \return The stored Sequence number field value.
     */
    uint32_t seq_number() const {
        return Endian::be_to_host(header_.seq_number);
    }
    
    /**
     *  \brief Getter for the ICV field.
     *  \return The stored ICV field value.
     */
    const byte_array& icv() const {
        return icv_;
    }

    // Setters

    /**
     *  \brief Setter for the Next header field.
     *  \param new_next_header The new Next header field value.
     */
    void next_header(uint8_t new_next_header);

    /**
     *  \brief Setter for the Length field.
     *  \param new_length The new Length field value.
     */
    void length(uint8_t new_length);

    /**
     *  \brief Setter for the Security Parameters Index field.
     *  \param new_spi The new Security Parameters Index field value.
     */
    void spi(uint32_t new_spi);

    /**
     *  \brief Setter for the Sequence number field.
     *  \param new_seq_number The new Sequence number field value.
     */
    void seq_number(uint32_t new_seq_number);
    
    /**
     *  \brief Setter for the ICV field.
     *  \param newicv_ The new ICV field value.
     */
    void icv(const byte_array& newicv_);

    /**
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \sa PDU::clone
     */
    IPSecAH* clone() const {
        return new IPSecAH(*this);
    }
private:
    struct ipsec_header {
        uint8_t next_header, length;
        uint32_t spi, seq_number;
    };

    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *);
    
    ipsec_header header_;
    byte_array icv_;
};

/**
 * \brief Represents an IPSec Authentication Header.
 */
class TINS_API IPSecESP : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::IPSEC_ESP;

    /**
     * \brief Default constructor.
     */
    IPSecESP();
    
    /**
     * \brief Constructs an IPSecESP object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this 
     * one.
     * 
     * If there is not enough size for an IPSecESP header, a 
     * malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    IPSecESP(const uint8_t* buffer, uint32_t total_sz);

    // Getters
    
    /**
     *  \brief Getter for the Security Parameters Index field.
     *  \return The stored Security Parameters Index field value.
     */
    uint32_t spi() const {
        return Endian::be_to_host(header_.spi);
    }

    /**
     *  \brief Getter for the Sequence number field.
     *  \return The stored Sequence number field value.
     */
    uint32_t seq_number() const {
        return Endian::be_to_host(header_.seq_number);
    }

    // Setters

    /**
     *  \brief Setter for the Security Parameters Index field.
     *  \param new_spi The new Security Parameters Index field value.
     */
    void spi(uint32_t new_spi);

    /**
     *  \brief Setter for the Sequence number field.
     *  \param new_seq_number The new Sequence number field value.
     */
    void seq_number(uint32_t new_seq_number);

    /**
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \sa PDU::clone
     */
    IPSecESP* clone() const {
        return new IPSecESP(*this);
    }
private:
    struct ipsec_header {
        uint32_t spi, seq_number;
    };

    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *);
    
    ipsec_header header_;
};
}

#endif // TINS_IPSEC_H
