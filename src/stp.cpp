/*
 * Copyright (c) 2012, Nasel
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

#include <cstring>
#include "stp.h"

namespace Tins {

STP::STP() 
: _header() 
{
    
}

STP::STP(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(_header))
        throw std::runtime_error("Not enough size.");
    std::memcpy(&_header, buffer ,sizeof(_header));
}

void STP::proto_id(uint16_t new_proto_id) {
    _header.proto_id = Endian::host_to_be(new_proto_id);
}

void STP::proto_version(uint8_t new_proto_version) {
    _header.proto_version = new_proto_version;
}

void STP::bpdu_type(uint8_t new_bpdu_type) {
    _header.bpdu_type = new_bpdu_type;
}

void STP::bpdu_flags(uint8_t new_bpdu_flags) {
    _header.bpdu_flags = new_bpdu_flags;
}

void STP::root_path_cost(uint32_t new_root_path_cost) {
    _header.root_path_cost = Endian::host_to_be(new_root_path_cost);
}

void STP::port_id(uint16_t new_port_id) {
    _header.port_id = Endian::host_to_be(new_port_id);
}

void STP::msg_age(uint16_t new_msg_age) {
    _header.msg_age = Endian::host_to_be<uint16_t>(new_msg_age * 256);
}

void STP::max_age(uint16_t new_max_age) {
    _header.max_age = Endian::host_to_be<uint16_t>(new_max_age * 256);
}

void STP::hello_time(uint16_t new_hello_time) {
    _header.hello_time = Endian::host_to_be<uint16_t>(new_hello_time * 256);
}

void STP::fwd_delay(uint16_t new_fwd_delay) {
    _header.fwd_delay = Endian::host_to_be<uint16_t>(new_fwd_delay * 256);
}

void STP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    
}

uint32_t STP::header_size() const {
    return sizeof(_header);
}
}

