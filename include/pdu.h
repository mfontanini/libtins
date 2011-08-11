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

#ifndef __PDU_H
#define __PDU_H


#include <stdint.h>
#include "packetsender.h"

namespace Tins {

    class PacketSender;

    class PDU {
    public:
        PDU(uint32_t flag, PDU *next_pdu = 0);
        virtual ~PDU();

        /* This PDU's header size only. */
        virtual uint32_t header_size() const = 0;
        /* This PDU's trailer size only. Defaults to 0. */
        virtual uint32_t trailer_size() const { return 0; }
        /* The size of the whole chain of PDUs, including this one. */
        inline uint32_t size() const;
        inline uint32_t flag() const { return _flag; }
        inline const PDU *inner_pdu() const { return _inner_pdu; }

        void flag(uint32_t new_flag);
        /* When setting a new inner_pdu, the instance takes
         * ownership of the object, therefore deleting it when
         * it's no longer required. */
        void inner_pdu(PDU *next_pdu);

        /* Serializes the whole chain of PDU's, including this one. */
        uint8_t *serialize(uint32_t &sz);

        /* */
        virtual bool send(PacketSender* sender) {return false;}
    protected:
        /* Serialize this PDU storing the result in buffer. */
        void serialize(uint8_t *buffer, uint32_t total_sz);

        /* Each PDU's own implementation of serialization. */
        virtual void write_serialization(uint8_t *buffer, uint32_t total_sz) = 0;
    private:
        uint32_t _flag;
        PDU *_inner_pdu;
    };
};

#endif
