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

#ifndef TINS_LOOPBACK_H
#define TINS_LOOPBACK_H

#include "pdu.h"
#include "macros.h"

namespace Tins {

/**
 * \brief Represents a Loopback PDU
 */
class TINS_API Loopback : public PDU {
public:
    /**
     * This PDU's type.
     */
    static const PDU::PDUType pdu_flag = PDU::LOOPBACK;

    /**
     * \brief Default constructs a Loopback PDU.
     * 
     * The family identifier is left as zero.
     */
    Loopback();
    
    /**
     * \brief Construct a Loopback object from a buffer and adds 
     * all identifiable PDUs found in the buffer as children of 
     * this one. 
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for a Loopback header, a 
     * malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Loopback(const uint8_t* buffer, uint32_t total_sz);
    
    /**
     * \brief Getter for the family identifier.
     * \return The stored family identifier.
     */
    uint32_t family() const {
        return family_;
    }
    
    /**
     * \brief Setter for the family identifier.
     * \param family_id The family identifier to be set.
     */
    void family(uint32_t family_id);
    
    /**
     * \sa PDU::header_size
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
     * \brief Check whether ptr points to a valid response for this PDU.
     *
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const;
    
    /**
     * \sa PDU::clone
     */
    Loopback* clone() const {
        return new Loopback(*this);
    }
    // Null/Loopback can only be sent in* BSD
    #ifdef BSD
    /**
     * \sa PDU::send()
     */
    void send(PacketSender& sender, const NetworkInterface& iface);
    #endif // BSD
private:
    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent);

    uint32_t family_;
};

} // Tins

#endif // TINS_LOOPBACK_H
