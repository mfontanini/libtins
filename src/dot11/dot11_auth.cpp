/*
 * Copyright (c) 2017, Matias Fontanini
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

#include <tins/dot11/dot11_auth.h>
#ifdef TINS_HAVE_DOT11

#include <cstring>
#include <tins/memory_helpers.h>

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

// Auth

Dot11Authentication::Dot11Authentication(const address_type& dst_hw_addr, 
                                         const address_type& src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr), body_() {
    subtype(Dot11::AUTH);
}

Dot11Authentication::Dot11Authentication(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(management_frame_size());
    stream.read(body_);
    parse_tagged_parameters(stream);
}

void Dot11Authentication::auth_algorithm(uint16_t new_auth_algorithm) {
    body_.auth_algorithm = Endian::host_to_le(new_auth_algorithm);
}

void Dot11Authentication::auth_seq_number(uint16_t new_auth_seq_number) {
    body_.auth_seq_number = Endian::host_to_le(new_auth_seq_number);
}

void Dot11Authentication::status_code(uint16_t new_status_code) {
    body_.status_code = Endian::host_to_le(new_status_code);
}

uint32_t Dot11Authentication::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(body_);
}

void Dot11Authentication::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(body_);
}

// Deauth

Dot11Deauthentication::Dot11Deauthentication(const address_type& dst_hw_addr, 
                                             const address_type& src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr), body_() {
    subtype(Dot11::DEAUTH);
}

Dot11Deauthentication::Dot11Deauthentication(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(management_frame_size());
    stream.read(body_);
    parse_tagged_parameters(stream);
}

void Dot11Deauthentication::reason_code(uint16_t new_reason_code) {
    body_.reason_code = Endian::host_to_le(new_reason_code);
}

uint32_t Dot11Deauthentication::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(body_);
}

void Dot11Deauthentication::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(body_);
}

} // namespace Tins

#endif // TINS_HAVE_DOT11
