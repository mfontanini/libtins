/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef TINS_LOOPBACK_H
#define TINS_LOOPBACK_H

#include "pdu.h"

namespace Tins {
class Loopback : public PDU {
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
     * \brief Construct a Loopback object.
     * 
     * \param family_id The family id to be used.
     * \param inner_pdu The inner pdu to be set.
     */
    Loopback(uint32_t family_id, PDU *inner_pdu = 0);
    
    /**
     * \brief Construct a Loopback object from a buffer.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Loopback(const uint8_t *buffer, uint32_t total_sz);
    
    /**
     * \brief Getter for the family identifier.
     * \return The stored family identifier.
     */
    uint32_t family() const { return _family; }
    
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
    PDUType pdu_type() const { return PDU::IP; }
    
    /**
     * \sa PDU::clone
     */
    Loopback *clone() const {
        return new Loopback(*this);
    }
private:
    void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

    uint32_t _family;
};
}

#endif // TINS_LOOPBACK_H
