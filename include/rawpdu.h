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
        /** \brief Creates an instance of RawPDU.
         *
         * The payload is not copied by default, therefore it must be 
         * manually freed by the user. If the payload was to be copied,
         * then the copy flag must be set to true.
         * \param pload The payload which the RawPDU will contain.
         * \param size The size of the payload.
         * \param copy Flag indicating wether to copy the payload.
         */
        RawPDU(uint8_t *pload, uint32_t size, bool copy = false);

        /** \brief RawPDU destructor.
         * 
         * Deletes the payload only if it was created setting the copy
         * flag to true.
         */
        ~RawPDU();

        /** \brief Getter for the payload.
         * 
         * \return The RawPDU's payload.
         */
        const uint8_t *payload() const { return _payload; }
        
        /** \brief Returns the header size.
         *
         * This metod overrides PDU::header_size. \sa PDU::header_size
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::RAW; }
    private:
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        uint8_t *_payload;
        uint32_t _payload_size;
        bool _owns_payload;
    };
};


#endif
