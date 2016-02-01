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

#include <cstring>
#include <algorithm>
#include "stp.h"
#include "exceptions.h"
#include "memory_helpers.h"

using std::copy;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

STP::STP() 
: header_() {
    
}

STP::STP(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
}

void STP::proto_id(uint16_t new_proto_id) {
    header_.proto_id = Endian::host_to_be(new_proto_id);
}

void STP::proto_version(uint8_t new_proto_version) {
    header_.proto_version = new_proto_version;
}

void STP::bpdu_type(uint8_t new_bpdu_type) {
    header_.bpdu_type = new_bpdu_type;
}

void STP::bpdu_flags(uint8_t new_bpdu_flags) {
    header_.bpdu_flags = new_bpdu_flags;
}

void STP::root_path_cost(uint32_t new_root_path_cost) {
    header_.root_path_cost = Endian::host_to_be(new_root_path_cost);
}

void STP::port_id(uint16_t new_port_id) {
    header_.port_id = Endian::host_to_be(new_port_id);
}

void STP::msg_age(uint16_t new_msg_age) {
    header_.msg_age = Endian::host_to_be<uint16_t>(new_msg_age * 256);
}

void STP::max_age(uint16_t new_max_age) {
    header_.max_age = Endian::host_to_be<uint16_t>(new_max_age * 256);
}

void STP::hello_time(uint16_t new_hello_time) {
    header_.hello_time = Endian::host_to_be<uint16_t>(new_hello_time * 256);
}

void STP::fwd_delay(uint16_t new_fwd_delay) {
    header_.fwd_delay = Endian::host_to_be<uint16_t>(new_fwd_delay * 256);
}

STP::bpdu_id_type STP::root_id() const {
    return convert(header_.root_id);
}

STP::bpdu_id_type STP::bridge_id() const {
    return convert(header_.bridge_id);
}

void STP::root_id(const bpdu_id_type& id) {
    header_.root_id = convert(id);
}
    
void STP::bridge_id(const bpdu_id_type& id) {
    header_.bridge_id = convert(id);
}

void STP::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    OutputMemoryStream stream(buffer, total_sz);
    stream.write(header_);
}

uint32_t STP::header_size() const {
    return sizeof(header_);
}

STP::bpdu_id_type STP::convert(const pvt_bpdu_id& id) {
    bpdu_id_type result(id.priority, 0, id.id);
    #if TINS_IS_LITTLE_ENDIAN
    result.ext_id = (id.ext_id << 8) | id.ext_idL;
    #else
    result.ext_id = id.ext_id;
    #endif
    return result;
}

STP::pvt_bpdu_id STP::convert(const bpdu_id_type& id) {
    pvt_bpdu_id result;
    result.priority = id.priority;
    copy(id.id.begin(), id.id.end(), result.id);
    #if TINS_IS_LITTLE_ENDIAN
    result.ext_id = (id.ext_id >> 8) & 0xf;
    result.ext_idL = id.ext_id & 0xff;
    #else
    result.ext_id = id.ext_id;
    #endif
    return result;
}

} // Tins
