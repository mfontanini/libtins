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

#ifndef WIN32
    #include <sys/socket.h>
#endif
#include <stdexcept>
#include <cassert>
#include "loopback.h"
#include "packet_sender.h"
#include "ip.h"
#include "llc.h"
#include "rawpdu.h"

namespace Tins {
Loopback::Loopback()
: _family()
{
    
}
    
Loopback::Loopback(uint32_t family_id, PDU *inner_pdu)
: PDU(inner_pdu), _family(family_id)
{
    
}

Loopback::Loopback(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(_family))
        throw std::runtime_error("Not enough size for a loopback PDU");
    _family = *reinterpret_cast<const uint32_t*>(buffer);
    buffer += sizeof(uint32_t);
    total_sz -= sizeof(uint32_t);
    if(total_sz) {
        switch(_family) {
            case PF_INET:
                inner_pdu(new Tins::IP(buffer, total_sz));
                break;
            case PF_LLC:
                inner_pdu(new Tins::LLC(buffer, total_sz));
                break;
            default:
                inner_pdu(new Tins::RawPDU(buffer, total_sz));
                break;
        };
    }
}
    
void Loopback::family(uint32_t family_id) {
    _family = family_id;
}

uint32_t Loopback::header_size() const {
    return sizeof(_family);
}

void Loopback::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) 
{
    assert(total_sz >= sizeof(_family));
    *reinterpret_cast<uint32_t*>(buffer) = _family;
}
}
