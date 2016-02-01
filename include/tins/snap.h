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

#ifndef TINS_SNAP_H
#define TINS_SNAP_H


#include <stdint.h>
#include "pdu.h"
#include "macros.h"
#include "endianness.h"
#include "small_uint.h"

namespace Tins {

/**
 * \class SNAP
 * \brief Represents a SNAP frame.
 * 
 * Note that this PDU contains the 802.3 LLC structure + SNAP frame.
 * So far only unnumbered information structure is supported.
 */
class TINS_API SNAP : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::SNAP;

    /**
     * \brief Creates an instance of SNAP
     * This constructor sets the dsap and ssap fields to 0xaa, and
     * the id field to 3.
     */
    SNAP();
    
    /**
     * \brief Constructs a SNAP object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for a SNAP header in the 
     * buffer, a malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    SNAP(const uint8_t* buffer, uint32_t total_sz);
    
    /* Setters */
    
    /**
     * \brief Setter for the Control field.
     * \param new_id The new Control to be set.
     */
    void control(uint8_t new_control);
    
    /**
     * \brief Setter for the Organization Code field.
     * \param new_org The new Organization Code to be set.
     */
    void org_code(small_uint<24> new_org);
    
    /**
     * \brief Setter for the Ethernet Type field.
     * \param new_eth The new Ethernet Type to be set.
     */
    void eth_type(uint16_t new_eth);
    
    /* Getters */
    
    /**
     * \brief Getter for the DSAP field.
     * \return The DSAP field.
     */
    uint8_t dsap() const {
        return snap_.dsap;
    }
    
    /**
     * \brief Getter for the SSAP field.
     * \return The SSAP field.
     */
    uint8_t ssap() const {
        return snap_.ssap;
    }
    
    /**
     * \brief Getter for the Control field.
     * \return The Control field.
     */
    uint8_t control() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return (snap_.control_org) & 0xff; 
        #else
        return (snap_.control_org >> 24) & 0xff; 
        #endif
    }
    
    /**
     * \brief Getter for the Organization Code field.
     * \return The Organization Code field.
     */        
    small_uint<24> org_code() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return Endian::be_to_host<uint32_t>(snap_.control_org & 0xffffff00);
        #else
        return snap_.control_org & 0xffffff;
        #endif
    }
    
    /**
     * \brief Getter for the Ethernet Type field.
     * \return The Ethernet Type field.
     */
    uint16_t eth_type() const {
        return Endian::be_to_host(snap_.eth_type);
    }
    
    /**
     * \brief Returns the SNAP frame's header length.
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
     * \brief Clones this PDU.
     * 
     * \sa PDU::clone
     */
    SNAP* clone() const {
        return new SNAP(*this);
    }    
private:
    TINS_BEGIN_PACK
    struct snap_header {
        uint8_t dsap;
        uint8_t ssap;
        uint32_t control_org;
        uint16_t eth_type;
    } TINS_END_PACK;
    
    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent);
    
    snap_header snap_;
};

} // Tins

#endif // TINS_SNAP_H
