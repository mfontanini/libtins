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
#include "bootp.h"
#include "exceptions.h"
#include "memory_helpers.h"

using std::copy;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins{

BootP::BootP() 
: bootp_(), vend_(64) {

}

BootP::BootP(const uint8_t* buffer, uint32_t total_sz, uint32_t vend_field_size) 
: vend_(vend_field_size) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(bootp_);
    if (!stream.can_read(vend_field_size)) {
        throw malformed_packet();
    }
    stream.read(vend_, vend_field_size);
}

uint32_t BootP::header_size() const {
    return static_cast<uint32_t>(sizeof(bootp_) + vend_.size());
}

void BootP::opcode(uint8_t code) {
    bootp_.opcode = code;
}

void BootP::htype(uint8_t type) {
    bootp_.htype = type;
}

void BootP::hlen(uint8_t length) {
    bootp_.hlen = length;
}

void BootP::hops(uint8_t count) {
    bootp_.hops = count;
}

void BootP::xid(uint32_t identifier) {
    bootp_.xid = Endian::host_to_be(identifier);
}

void BootP::secs(uint16_t value) {
    bootp_.secs = Endian::host_to_be(value);
}

void BootP::padding(uint16_t value) {
    bootp_.padding = Endian::host_to_be(value);
}

void BootP::ciaddr(ipaddress_type address) {
    bootp_.ciaddr = address;
}

void BootP::yiaddr(ipaddress_type address) {
    bootp_.yiaddr = address;
}

void BootP::siaddr(ipaddress_type address) {
    bootp_.siaddr = address;
}

void BootP::giaddr(ipaddress_type address) {
    bootp_.giaddr = address;
}

void BootP::sname(const uint8_t* new_sname) {
    copy(new_sname, new_sname + sizeof(bootp_.sname), bootp_.sname);
}

void BootP::file(const uint8_t* new_file) {
    copy(new_file, new_file + sizeof(bootp_.file), bootp_.file);
}

void BootP::vend(const vend_type& newvend_) {
    vend_ = newvend_;
}

void BootP::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent) {
    OutputMemoryStream stream(buffer, total_sz);
    stream.write(bootp_);
    stream.write(vend_.begin(), vend_.end());
}

bool BootP::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(bootp_)) {
        return false;
    }
    const bootp_header* bootp_ptr = (const bootp_header *)ptr;
    return bootp_ptr->xid == bootp_.xid;
}

} // Tins
