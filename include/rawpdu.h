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

#ifndef TINS_RAWPDU_H
#define TINS_RAWPDU_H

#include <vector>
#include "pdu.h"

namespace Tins {

    /** \brief Represents a PDU which holds raw data.
     *
     * In order to send payloads over TCP, UDP, or other transport layer or
     * higher level protocols, RawPDU can be used as a wrapper for raw byte arrays.
     */
    class RawPDU : public PDU {
    public:
        /**
         * The type used to store the payload.
         */
        typedef std::vector<uint8_t> payload_type;
        
        /**
         * This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::RAW;
    
        /** 
         * \brief Creates an instance of RawPDU.
         *
         * The payload is copied, therefore the original payload's memory
         * must be freed by the user.
         * \param pload The payload which the RawPDU will contain.
         * \param size The size of the payload.
         */
        RawPDU(const uint8_t *pload, uint32_t size);

        /**
         * \brief Setter for the payload field
         * \param pload The payload to be set.
         */
        void payload(const payload_type &pload);

        /**
         * \brief Setter for the payload field
         * \param start The start of the new payload.
         * \param end The end of the new payload.
         */
        template<typename ForwardIterator>
        void payload(ForwardIterator start, ForwardIterator end) {
            _payload.assign(start, end);
        }

        /** 
         * \brief Const getter for the payload.
         * \return The RawPDU's payload.
         */
        const payload_type &payload() const { return _payload; }
        
        /** 
         * \brief Non-const getter for the payload.
         * \return The RawPDU's payload.
         */
        payload_type &payload() { return _payload; }
        
        /** 
         * \brief Returns the header size.
         * 
         * This returns the same as RawPDU::payload_size().
         *
         * This metod overrides PDU::header_size. \sa PDU::header_size
         */
        uint32_t header_size() const;
        
        /** 
         * \brief Returns the payload size.
         *
         * \return uint32_t containing the payload size.
         */
        uint32_t payload_size() const {
            return _payload.size();
        }

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::RAW; }
        
        /**
         * \sa PDU::clone
         */
        RawPDU *clone() const {
            return new RawPDU(*this);
        }
    private:
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        payload_type _payload;
    };
};


#endif // TINS_RAWPDU_H
