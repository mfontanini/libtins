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

#include "dot11/dot11_auth.h"
#ifdef HAVE_DOT11

#include <cassert>
#include <cstring>

namespace Tins {
/* Auth */

Dot11Authentication::Dot11Authentication(const address_type &dst_hw_addr, 
const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::AUTH);
    memset(&_body, 0, sizeof(_body));
}

Dot11Authentication::Dot11Authentication(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) 
{
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw malformed_packet();
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11Authentication::auth_algorithm(uint16_t new_auth_algorithm) {
    this->_body.auth_algorithm = Endian::host_to_le(new_auth_algorithm);
}

void Dot11Authentication::auth_seq_number(uint16_t new_auth_seq_number) {
    this->_body.auth_seq_number = Endian::host_to_le(new_auth_seq_number);
}

void Dot11Authentication::status_code(uint16_t new_status_code) {
    this->_body.status_code = Endian::host_to_le(new_status_code);
}

uint32_t Dot11Authentication::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(_body);
}

uint32_t Dot11Authentication::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    #ifdef TINS_DEBUG
    assert(sz <= total_sz);
    #endif
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* Deauth */

Dot11Deauthentication::Dot11Deauthentication(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr)
{
    this->subtype(Dot11::DEAUTH);
    memset(&_body, 0, sizeof(_body));
}

Dot11Deauthentication::Dot11Deauthentication(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw malformed_packet();
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11Deauthentication::reason_code(uint16_t new_reason_code) {
    this->_body.reason_code = Endian::host_to_le(new_reason_code);
}

uint32_t Dot11Deauthentication::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(this->_body);
}

uint32_t Dot11Deauthentication::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    #ifdef TINS_DEBUG
    assert(sz <= total_sz);
    #endif
    memcpy(buffer, &this->_body, sz);
    return sz;
}
} // namespace Tins

#endif // HAVE_DOT11
