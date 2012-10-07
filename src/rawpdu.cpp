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
#include <algorithm>
#include "rawpdu.h"


namespace Tins {
RawPDU::RawPDU(const uint8_t *pload, uint32_t size) 
: _payload(pload, pload + size) 
{
    
}

RawPDU::RawPDU(const std::string &data) 
: _payload(data.begin(), data.end()) {
    
}

uint32_t RawPDU::header_size() const {
    return _payload.size();
}

void RawPDU::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    assert(total_sz >= _payload.size());
    std::copy(_payload.begin(), _payload.end(), buffer);
}

void RawPDU::payload(const payload_type &pload) {
    _payload = pload;
}
}
