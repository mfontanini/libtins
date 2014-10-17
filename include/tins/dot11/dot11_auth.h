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

#include "../config.h"

#if !defined(TINS_DOT11_DOT11_AUTH_H) && defined(HAVE_DOT11)
#define TINS_DOT11_DOT11_AUTH_H

#include "../dot11/dot11_mgmt.h"

namespace Tins {
/**
 * \brief IEEE 802.11 Authentication Request frame.
 */
class Dot11Authentication : public Dot11ManagementFrame {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_AUTH;

    /**
     * \brief Constructor for creating a 802.11 Authentication.
     *
     * Constructs a 802.11 Dot11Authentication taking the 
     * destination and source hardware address.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11Authentication(const address_type &dst_hw_addr = address_type(), 
                        const address_type &src_hw_addr = address_type());

    /**
     * \brief Constructs a Dot11Authentication object from a buffer 
     * and adds all identifiable PDUs found in the buffer as children 
     * of this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for the header in the buffer
     * or the input data is malformed, a malformed_packet exception 
     * is thrown.
     *
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11Authentication(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Getter for the Authetication Algorithm Number field.
     *
     * \return The stored authentication algorithm number.
     */
    uint16_t auth_algorithm() const {return Endian::le_to_host(_body.auth_algorithm); }

    /**
     * \brief Getter for the Authetication Sequence Number field.
     *
     * \return The stored authentication sequence number.
     */
    uint16_t auth_seq_number() const {return Endian::le_to_host(_body.auth_seq_number); }

    /**
     * \brief Getter for the status code field.
     *
     * \return The stored status code.
     */
    uint16_t status_code() const { return Endian::le_to_host(_body.status_code); }

    /**
     * \brief Setter for the Authetication Algorithm Number field.
     *
     * \param new_auth_algorithm The Authetication Algorithm Number 
     * to be set.
     */
    void auth_algorithm(uint16_t new_auth_algorithm);

    /**
     * \brief Setter for the Authetication Sequence Number field.
     *
     * \param new_auth_seq_number The Authetication Sequence Number 
     * to be set.
     */
    void auth_seq_number(uint16_t new_auth_seq_number);

    /**
     * \brief Setter for the status code field.
     *
     * \param new_status_code The status code to be set.
     */
    void status_code(uint16_t new_status_code);

    /**
     * \brief Returns the frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Check wether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11Authentication *clone() const {
        return new Dot11Authentication(*this);
    }
private:
    struct AuthBody {
        uint16_t auth_algorithm;
        uint16_t auth_seq_number;
        uint16_t status_code;
    };

    uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

    AuthBody _body;

};

/**
 * \brief IEEE 802.11 Deauthentication frame.
 *
 */
class Dot11Deauthentication : public Dot11ManagementFrame {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_DEAUTH;

    /**
     * \brief Constructor for creating a 802.11 Deauthentication.
     *
     * Constructs a 802.11 Deauthentication taking the 
     * destination and source hardware address.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11Deauthentication(const address_type &dst_hw_addr = address_type(), 
                        const address_type &src_hw_addr = address_type());

    /**
     * \brief Constructs a Dot11Deauthentication object from a buffer 
     * and adds all identifiable PDUs found in the buffer as children 
     * of this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for the header in the buffer
     * or the input data is malformed, a malformed_packet exception 
     * is thrown.
     *
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11Deauthentication(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Getter for the reason code field.
     *
     * \return The reason code to be set.
     */
    uint16_t reason_code() const { return Endian::le_to_host(_body.reason_code); }

    /**
     * \brief Setter for the reason code field.
     *
     * \param new_reason_code The reason code to be set.
     */
    void reason_code(uint16_t new_reason_code);

    /**
     * \brief Returns the frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Check wether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11Deauthentication *clone() const {
        return new Dot11Deauthentication(*this);
    }
private:
    struct DeauthBody {
        uint16_t reason_code;
    };

    uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

    DeauthBody _body;
};
} // namespace Tins


#endif // TINS_DOT11_DOT11_AUTH_H
