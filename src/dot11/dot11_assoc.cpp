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

#include "dot11/dot11_assoc.h"
#ifdef TINS_HAVE_DOT11

#include <cstring>
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

// Disassoc

Dot11Disassoc::Dot11Disassoc(const address_type& dst_hw_addr, 
                             const address_type& src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr), body_() {
this->subtype(Dot11::DISASSOC);
}

Dot11Disassoc::Dot11Disassoc(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(management_frame_size());
    stream.read(body_);
    parse_tagged_parameters(stream);
}

void Dot11Disassoc::reason_code(uint16_t new_reason_code) {
    body_.reason_code = Endian::host_to_le(new_reason_code);
}

uint32_t Dot11Disassoc::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(body_);
}

void Dot11Disassoc::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(body_);
}

// Assoc request

Dot11AssocRequest::Dot11AssocRequest(const address_type& dst_hw_addr, 
                                     const address_type& src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr), body_() {
    subtype(Dot11::ASSOC_REQ);
}

Dot11AssocRequest::Dot11AssocRequest(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(management_frame_size());
    stream.read(body_);
    parse_tagged_parameters(stream);
}

void Dot11AssocRequest::listen_interval(uint16_t new_listen_interval) {
    body_.listen_interval = Endian::host_to_le(new_listen_interval);
}

uint32_t Dot11AssocRequest::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(body_);
}

void Dot11AssocRequest::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(body_);
}

// Assoc response

Dot11AssocResponse::Dot11AssocResponse(const address_type& dst_hw_addr, 
                                       const address_type& src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr), body_() {
    subtype(Dot11::ASSOC_RESP);
}

Dot11AssocResponse::Dot11AssocResponse(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(management_frame_size());
    stream.read(body_);
    parse_tagged_parameters(stream);
}

void Dot11AssocResponse::status_code(uint16_t new_status_code) {
    body_.status_code = Endian::host_to_le(new_status_code);
}

void Dot11AssocResponse::aid(uint16_t new_aid) {
    body_.aid = Endian::host_to_le(new_aid);
}

uint32_t Dot11AssocResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(body_);
}

void Dot11AssocResponse::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(body_);
}

// ReAssoc request

Dot11ReAssocRequest::Dot11ReAssocRequest(const address_type& dst_hw_addr, 
                                         const address_type& src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr), body_() {
    subtype(Dot11::REASSOC_REQ);
}

Dot11ReAssocRequest::Dot11ReAssocRequest(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(management_frame_size());
    stream.read(body_);
    parse_tagged_parameters(stream);
}

void Dot11ReAssocRequest::listen_interval(uint16_t new_listen_interval) {
    body_.listen_interval = Endian::host_to_le(new_listen_interval);
}

void Dot11ReAssocRequest::current_ap(const address_type& new_current_ap) {
    new_current_ap.copy(body_.current_ap);
}

uint32_t Dot11ReAssocRequest::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(body_);
}

void Dot11ReAssocRequest::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(body_);
}

// ReAssoc response

Dot11ReAssocResponse::Dot11ReAssocResponse(const address_type& dst_hw_addr, 
                                           const address_type& src_hw_addr)
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr), body_() {
    subtype(Dot11::REASSOC_RESP);
}

Dot11ReAssocResponse::Dot11ReAssocResponse(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(management_frame_size());
    stream.read(body_);
    parse_tagged_parameters(stream);
}

void Dot11ReAssocResponse::status_code(uint16_t new_status_code) {
    body_.status_code = Endian::host_to_le(new_status_code);
}

void Dot11ReAssocResponse::aid(uint16_t new_aid) {
    body_.aid = Endian::host_to_le(new_aid);
}

uint32_t Dot11ReAssocResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(body_);
}

void Dot11ReAssocResponse::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(body_);
}

} // Tins

#endif // TINS_HAVE_DOT11
