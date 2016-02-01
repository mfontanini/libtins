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

#include <stdexcept>
#include <cstring>
#include "sll.h"
#include "internals.h"
#include "exceptions.h"
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

SLL::SLL() : header_() {
    
}
    
SLL::SLL(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    if (stream) {
        inner_pdu(
            Internals::pdu_from_flag(
                (Constants::Ethernet::e)protocol(), 
                stream.pointer(), 
                stream.size()
            )
        );
    }
}

void SLL::packet_type(uint16_t new_packet_type) {
    header_.packet_type = Endian::host_to_be(new_packet_type);
}

void SLL::lladdr_type(uint16_t new_lladdr_type) {
    header_.lladdr_type = Endian::host_to_be(new_lladdr_type);
}

void SLL::lladdr_len(uint16_t new_lladdr_len) {
    header_.lladdr_len = Endian::host_to_be(new_lladdr_len);
}

void SLL::address(const address_type& new_address) {
    new_address.copy(header_.address);
}

void SLL::protocol(uint16_t new_protocol) {
    header_.protocol = Endian::host_to_be(new_protocol);
}

uint32_t SLL::header_size() const {
    return sizeof(header_);
}

void SLL::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    OutputMemoryStream stream(buffer, total_sz);
    if (inner_pdu()) {
        Constants::Ethernet::e flag = Internals::pdu_flag_to_ether_type(
            inner_pdu()->pdu_type()
        );
        protocol(static_cast<uint16_t>(flag));
    }
    stream.write(header_);
}

} // Tins
