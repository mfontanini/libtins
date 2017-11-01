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

#ifndef TINS_MPLS_H
#define TINS_MPLS_H

#include <tins/pdu.h>
#include <tins/endianness.h>
#include <tins/macros.h>
#include <tins/small_uint.h>

namespace Tins {

class ICMPExtension;

/**
 * \class MPLS
 * \brief Represents an MPLS PDU
 */
class TINS_API MPLS : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::MPLS;

    /**
     * \brief Default constructor
     */
    MPLS();

    /**
     * \brief Construct an MPLS layer from an ICMP extension
     *
     * This will use the extension's payload to build this packet. 
     * The extension's class and type are not checked.
     *
     */
    MPLS(const ICMPExtension& extension);

    /**
     * \brief Constructor from buffer
     */
    MPLS(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the label field.
     */
    small_uint<20> label() const {
        return (Endian::be_to_host(header_.label_high) << 4) |
               ((header_.label_low_exp_and_bottom >> 4) & 0xf);
    }

    /**
     * \brief Getter for the experimental field.
     */
    small_uint<3> experimental() const {
        return (header_.label_low_exp_and_bottom >> 1) & 0x7;
    }

    /**
     * \brief Getter for the bottom of the stack field.
     */
    small_uint<1> bottom_of_stack() const {
        return header_.label_low_exp_and_bottom & 0x1;
    }

    /**
     * \brief Getter for the ttl field.
     */
    uint8_t ttl() const {
        return header_.ttl;
    }

    /**
     * \brief Setter for the label field
     *
     * \param value The new label field value
     */
    void label(small_uint<20> value);

    /**
     * \brief Setter for the experimental field
     *
     * \param value The new experimental field value
     */
    void experimental(small_uint<3> value);

    /**
     * \brief Setter for the bottom of the stack field
     *
     * Note that if this MPLS layer is somewhere between an Ethernet and IP
     * layers, the bottom of the stack field will be overriden and set
     * automatically. You should only set this field when constructing ICMP
     * extensions.
     *
     * \param value The new bottom of the stack field value
     */
    void bottom_of_stack(small_uint<1> value);

    /**
     * \brief Setter for the ttl field
     *
     * \param value The new ttl field value
     */
    void ttl(uint8_t value);

    /**
     * \brief Returns the MPLS frame's header length.
     *
     * \return The header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

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
    MPLS* clone() const {
        return new MPLS(*this);
    }
private:
    TINS_BEGIN_PACK
    struct mpls_header {
        uint16_t label_high;
        uint8_t label_low_exp_and_bottom;
        uint8_t ttl;
    } TINS_END_PACK;

    void write_serialization(uint8_t* buffer, uint32_t total_sz);

    mpls_header header_;
};

} // Tins

#endif // TINS_MPLS_H
