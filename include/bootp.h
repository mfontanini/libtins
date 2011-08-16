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

#ifndef __BOOTP_H
#define __BOOTP_H

#include <stdint.h>

#include <stdint.h>

#include "pdu.h"

namespace Tins {

    /**
     * \brief Class representing a BootP packet.
     */
    class BootP : public PDU {

    public:
        /**
         * \brief Enum which contains the different opcodes BootP messages.
         */
         enum OpCodes {
            BOOTREQUEST = 1,
            BOOTREPLY = 2
         }

    private:
        /**
         * Struct that represents the Bootp datagram.
         */
        struct bootp {
            uint8_t opcode;
            uint8_t htype;
            uint8_t hlen;
            uint8_t hops;
            uint32_t xid;
            uint16_t secs;
            uint16_t padding;
            uint32_t ciaddr;
            uint32_t yiaddr;
            uint32_t siaddr;
            uint32_t giaddr;
            uint8_t chaddr[16];
            uint8_t sname[64];
            uint8_t file[128];
            uint8_t vend[64];
        } __attribute__((__packed__));


    }

}

#endif
