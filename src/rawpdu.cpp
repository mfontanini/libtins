/*
 * Copyright (c) 2014, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef TINS_DEBUG
#include <cassert>
#endif
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
    #ifdef TINS_DEBUG
    assert(total_sz >= _payload.size());
    #endif
    std::copy(_payload.begin(), _payload.end(), buffer);
}

void RawPDU::payload(const payload_type &pload) {
    _payload = pload;
}

bool RawPDU::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    return true;
}
}
