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

#include "dot11/dot11_assoc.h"
#ifdef HAVE_DOT11

#include <cassert>
#include <cstring>

namespace Tins {
/* Diassoc */

Dot11Disassoc::Dot11Disassoc(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr)
{
    this->subtype(Dot11::DISASSOC);
    memset(&_body, 0, sizeof(_body));
}

Dot11Disassoc::Dot11Disassoc(const uint8_t *buffer, uint32_t total_sz) 
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

void Dot11Disassoc::reason_code(uint16_t new_reason_code) {
    this->_body.reason_code = Endian::host_to_le(new_reason_code);
}

uint32_t Dot11Disassoc::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(DisassocBody);
}

uint32_t Dot11Disassoc::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(DisassocBody);
    #ifdef TINS_DEBUG
    assert(sz <= total_sz);
    #endif
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* Assoc request. */

Dot11AssocRequest::Dot11AssocRequest(const address_type &dst_hw_addr, 
const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr)
{
    subtype(Dot11::ASSOC_REQ);
    memset(&_body, 0, sizeof(_body));
}

Dot11AssocRequest::Dot11AssocRequest(const uint8_t *buffer, uint32_t total_sz) 
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

void Dot11AssocRequest::listen_interval(uint16_t new_listen_interval) {
    this->_body.listen_interval = Endian::host_to_le(new_listen_interval);
}

uint32_t Dot11AssocRequest::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(AssocReqBody);
}

uint32_t Dot11AssocRequest::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(AssocReqBody);
    #ifdef TINS_DEBUG
    assert(sz <= total_sz);
    #endif
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* Assoc response. */

Dot11AssocResponse::Dot11AssocResponse(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    subtype(Dot11::ASSOC_RESP);
    memset(&_body, 0, sizeof(_body));
}

Dot11AssocResponse::Dot11AssocResponse(const uint8_t *buffer, uint32_t total_sz) 
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

void Dot11AssocResponse::status_code(uint16_t new_status_code) {
    this->_body.status_code = Endian::host_to_le(new_status_code);
}

void Dot11AssocResponse::aid(uint16_t new_aid) {
    this->_body.aid = Endian::host_to_le(new_aid);
}

uint32_t Dot11AssocResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(AssocRespBody);
}

uint32_t Dot11AssocResponse::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(AssocRespBody);
    #ifdef TINS_DEBUG
    assert(sz <= total_sz);
    #endif
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* ReAssoc request. */

Dot11ReAssocRequest::Dot11ReAssocRequest(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr)
{
    this->subtype(Dot11::REASSOC_REQ);
    memset(&_body, 0, sizeof(_body));
}

Dot11ReAssocRequest::Dot11ReAssocRequest(const uint8_t *buffer, uint32_t total_sz) 
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

void Dot11ReAssocRequest::listen_interval(uint16_t new_listen_interval) {
    this->_body.listen_interval = Endian::host_to_le(new_listen_interval);
}

void Dot11ReAssocRequest::current_ap(const address_type &new_current_ap) {
    new_current_ap.copy(_body.current_ap);
}

uint32_t Dot11ReAssocRequest::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(this->_body);
}

uint32_t Dot11ReAssocRequest::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    #ifdef TINS_DEBUG
    assert(sz <= total_sz);
    #endif
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* ReAssoc response. */

Dot11ReAssocResponse::Dot11ReAssocResponse(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr)
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::REASSOC_RESP);
    memset(&_body, 0, sizeof(_body));
}

Dot11ReAssocResponse::Dot11ReAssocResponse(const uint8_t *buffer, uint32_t total_sz) 
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

void Dot11ReAssocResponse::status_code(uint16_t new_status_code) {
    this->_body.status_code = Endian::host_to_le(new_status_code);
}

void Dot11ReAssocResponse::aid(uint16_t new_aid) {
    this->_body.aid = Endian::host_to_le(new_aid);
}

uint32_t Dot11ReAssocResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(this->_body);
}

uint32_t Dot11ReAssocResponse::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    #ifdef TINS_DEBUG
    assert(sz <= total_sz);
    #endif
    memcpy(buffer, &this->_body, sz);
    return sz;
}
} // namespace Tins

#endif // HAVE_DOT11
