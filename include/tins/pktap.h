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

#ifndef TINS_PKTAP_H
#define TINS_PKTAP_H

#include "pdu.h"

namespace Tins {

class PKTAP : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::PKTAP;

    /**
     * Default constructor.
     */
    PKTAP();

    /**
     * \brief Constructs a PKTAP object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this 
     * one.
     * 
     * If there is not enough size for an IP header, a 
     * malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    PKTAP(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Returns the header size.
     *
     * This metod overrides PDU::header_size. 
     * \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \sa PDU::clone
     */
    PKTAP *clone() const {
        return new PKTAP(*this);
    }
private:
    struct pktap_header {
        uint32_t length;
        uint32_t next;
        uint32_t dlt;
        uint8_t pth_ifname[24];
        uint32_t flags;
        uint32_t protocol_family;
        uint32_t header_length;
        uint32_t trailer_length;
        uint32_t pid;
        uint8_t command[20];
        uint32_t service_class;
        uint16_t interface_type;
        uint16_t interface_unit;
        uint32_t epid;
        uint8_t ecommand[20];
    };

    void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);


    pktap_header header_;
};

} // Tins

#endif // TINS_PKTAP_H
