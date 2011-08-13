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

#ifndef __RAWPDU_H
#define __RAWPDU_H


#include "pdu.h"


namespace Tins {
    
    /** \brief Represents a PDU which holds raw data.
     * 
     * In order to send payloads over TCP, UDP, or other transport layer or
     * higher level protocols, RawPDU can be used as a wrapper for raw byte arrays.
     */
    class RawPDU : public PDU {
    public:
        RawPDU(uint8_t *payload, uint32_t size);
        
        /** \brief Returns the header size.
         * 
         * This metod overrides PDU::header_size. \sa PDU::header_size
         */
        uint32_t header_size() const;
    private:
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
    
        uint8_t *_payload;
        uint32_t _payload_size;
    };
};


#endif
