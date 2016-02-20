/*
 * Copyright (c) 2016, Matias Fontanini
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

#include "dot11/dot11_probe.h"

#ifdef TINS_HAVE_DOT11

#include <cstring>
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

// Probe Request

Dot11ProbeRequest::Dot11ProbeRequest(const address_type& dst_hw_addr, 
                                     const address_type& src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) {
    subtype(Dot11::PROBE_REQ);
}

Dot11ProbeRequest::Dot11ProbeRequest(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(management_frame_size());
    parse_tagged_parameters(stream);
}

// Probe Response

Dot11ProbeResponse::Dot11ProbeResponse(const address_type& dst_hw_addr, 
                                       const address_type& src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr), body_() {
    subtype(Dot11::PROBE_RESP);
}

Dot11ProbeResponse::Dot11ProbeResponse(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(management_frame_size());
    stream.read(body_);
    parse_tagged_parameters(stream);
}

void Dot11ProbeResponse::timestamp(uint64_t new_timestamp) {
    body_.timestamp = Endian::host_to_le(new_timestamp);
}

void Dot11ProbeResponse::interval(uint16_t new_interval) {
    body_.interval = Endian::host_to_le(new_interval);
}

uint32_t Dot11ProbeResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(body_);
}

void Dot11ProbeResponse::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(body_);
}

} // namespace Tins

#endif // TINS_HAVE_DOT11
