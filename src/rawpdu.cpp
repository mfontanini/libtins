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

#include <cassert>
#include <cstring>
#include "rawpdu.h"
#include <iostream>


Tins::RawPDU::RawPDU(uint8_t *payload, uint32_t size) : PDU(255), _payload(payload), _payload_size(size) {
    
}

uint32_t Tins::RawPDU::header_size() const {
    return _payload_size;
}

void Tins::RawPDU::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    assert(total_sz >= _payload_size);
    std::memcpy(buffer, _payload, _payload_size);
}

