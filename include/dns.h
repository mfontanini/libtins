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

#ifndef __DNS_H
#define __DNS_H

#include <stdint.h>
#include "pdu.h"

namespace Tins {
    class DNS : public PDU {
    public:
        enum QRType {
            QUERY = 0,
            RESPONSE = 1
        };
        
        /**
         * \brief Setter for the id field.
         * 
         * \param new_id The new id to be set.
         */
        void id(uint16_t new_id);
        
        /**
         * \brief Setter for the query response field.
         * 
         * \param new_qr The new qr to be set.
         */
        void type(QRType new_qr);
        
        /**
         * \brief Setter for the opcode field.
         * 
         * \param new_opcode The new opcode to be set.
         */
        void opcode(uint8_t new_opcode);
        
        /**
         * \brief Setter for the authoritative answer field.
         * 
         * \param new_aa The new authoritative answer field value to 
         * be set.
         */
        void authoritative_answer(uint8_t new_aa);
        
        /**
         * \brief Setter for the truncated field.
         * 
         * \param new_tc The new truncated field value to 
         * be set.
         */
        void truncated(uint8_t new_tc);
        
        /**
         * \brief Setter for the recursion desired field.
         * 
         * \param new_rd The new recursion desired value to 
         * be set.
         */
        void recursion_desired(uint8_t new_rd);
        
        /**
         * \brief Setter for the recursion available field.
         * 
         * \param new_ra The new recursion available value to 
         * be set.
         */
        void recursion_available(uint8_t new_ra);
        
        /**
         * \brief Setter for the z(reserved) field.
         * 
         * \param new_z The new z value to be set.
         */
        void z(uint8_t new_z);
        
        /**
         * \brief Setter for the authenticated data field.
         * 
         * \param new_ad The new authenticated data value to 
         * be set.
         */
        void authenticated_data(uint8_t new_ad);
        
        /**
         * \brief Setter for the checking disabled field.
         * 
         * \param new_z The new checking disabled value to be set.
         */
        void checking_disabled(uint8_t new_cd);
        
        /**
         * \brief Setter for the rcode field.
         * 
         * \param new_rcode The new rcode value to be set.
         */
        void rcode(uint8_t new_rcode);
    private:
        struct dnshdr {
            uint16_t id;
            uint16_t 
                qr:1,
                opcode:4,
                aa:1,
                tc:1,
                rd:1,
                ra:1,
                z:1,
                ad:1,
                cd:1,
                rcode:4;
            uint32_t questions, answers,
                     authority, additional;
        };
        
        dnshdr dns;
    };
};

#endif // __DNS_H
