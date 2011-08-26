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

#ifndef __IEEE8022_H
#define __IEEE8022_H


#include <stdint.h>
#include "pdu.h"

namespace Tins {

    /**
     * \brief Class representing a SNAP frame.
     * 
     * So far only unnumbered information structure is supported.
     */
    class SNAP : public PDU {
    public:
        /**
         * \brief Creates an instance of SNAP
         * \param child The child PDU.(optional)
         */
        SNAP(PDU *child = 0);
        
        /**
         * \brief Constructor which creates a SNAP object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        SNAP(const uint8_t *buffer, uint32_t total_sz);
        
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
        PDUType pdu_type() const { return PDU::SNAP; }
    private:
        struct snaphdr {
            uint8_t dsap;
            uint8_t ssap;
            uint32_t id:2,
                reserved1:2,
                poll:2,
                reserved2:2,
                org_code:24;
            uint16_t eth_type;
        } __attribute__((__packed__));
        
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        snaphdr _snap;
    };
    
};

#endif
