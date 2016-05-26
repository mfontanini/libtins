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

#ifndef TINS_UDP_H
#define TINS_UDP_H

#include "macros.h"
#include "pdu.h"
#include "endianness.h"

namespace Tins {

/** 
 * \class UDP
 * \brief Represents an UDP PDU.
 *
 * This class represents an UDP PDU. 
 * 
 * While sniffing, the payload sent in each packet will be wrapped
 * in a RawPDU, which is set as the UDP object's inner_pdu. Therefore,
 * if you are sniffing and want to see the UDP packet's payload,
 * you need to do the following:
 *
 * \code
 * // Get a packet from somewhere.
 * UDP udp = ...;
 *
 * // Extract the RawPDU object.
 * const RawPDU& raw = udp.rfind_pdu<RawPDU>();
 *
 * // Finally, take the payload (this is a vector<uint8_t>)
 * const RawPDU::payload_type& payload = raw.payload();
 * \endcode
 *
 * \sa RawPDU
 */
class TINS_API UDP : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::UDP;

    /**
     * \brief Extracts metadata for this protocol based on the buffer provided
     *
     * \param buffer Pointer to a buffer
     * \param total_sz Size of the buffer pointed by buffer
     */
    static metadata extract_metadata(const uint8_t *buffer, uint32_t total_sz);

    /** 
     * \brief UDP constructor.
     *
     * Constructs an instance of UDP. The destination and source 
     * port can be provided, otherwise both of them will be 0.
     * 
     * \param dport Destination port.
     * \param sport Source port.
     * */
    UDP(uint16_t dport = 0, uint16_t sport = 0);

    /**
     * \brief Constructs an UDP object from a buffer.
     * 
     * If there is not enough size for a UDP header a malformed_packet 
     * exception is thrown.
     * 
     * Any extra data will be stored in a RawPDU.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    UDP(const uint8_t* buffer, uint32_t total_sz);
    
    /** 
     * \brief Getter for the destination port.
     * \return The datagram's destination port.
     */
    uint16_t dport() const {
        return Endian::be_to_host(header_.dport);
    }

    /** 
     * \brief Getter for the source port.
     * \return The datagram's source port.
     */
    uint16_t sport() const {
        return Endian::be_to_host(header_.sport);
    }
    
    /**
     * \brief Getter for the length of the datagram.
     * \return The length of the datagram.
     */
    uint16_t length() const {
        return Endian::be_to_host(header_.len);
    }
    
    /**
     * \brief Getter for the checksum of the datagram.
     * \return The datagram's checksum.
     */
    uint16_t checksum() const {
        return Endian::be_to_host(header_.check);
    }

    /** 
     * \brief Set the destination port.
     * \param new_dport The new destination port.
     */
    void dport(uint16_t new_dport);

    /** 
     * \brief Set the source port.
     *
     * \param new_sport The new source port.
     */
    void sport(uint16_t new_sport);
    
    /** 
     * \brief Set the length field.
     * \param new_len The new length field.
     */
    void length(uint16_t new_len);

    /**
     * \brief Check whether ptr points to a valid response for this PDU.
     *
     * This compares the source and destination ports in the provided
     * response with those stored in this PDU.
     * 
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const;

    /** 
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. This size includes the
     * payload and options size. \sa PDU::header_size
     */
    uint32_t header_size() const;
    
    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return PDU::UDP; }
    
    /**
     * \sa PDU::clone
     */
    UDP* clone() const {
        return new UDP(*this);
    }
private:
    TINS_BEGIN_PACK
    struct udp_header {
        uint16_t sport;
        uint16_t dport;
        uint16_t len;
        uint16_t check;
    } TINS_END_PACK;

    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent);

    udp_header header_;
};

} // Tins

#endif // TINS_UDP_H
