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
#include "dot1q.h"
#include "internals.h"
#include "exceptions.h"
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PDU::metadata Dot1Q::extract_metadata(const uint8_t *buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(dot1q_header))) {
        throw malformed_packet();
    }
    return metadata(sizeof(dot1q_header), pdu_flag, PDU::UNKNOWN);
}

Dot1Q::Dot1Q(small_uint<12> tag_id, bool append_pad)
: header_(), append_padding_(append_pad) {
    id(tag_id);
}

Dot1Q::Dot1Q(const uint8_t* buffer, uint32_t total_sz)
: append_padding_() {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);

    if (stream) {
        inner_pdu(
            Internals::pdu_from_flag(
                (Constants::Ethernet::e)payload_type(),
                stream.pointer(),
                stream.size()
            )
        );
    }
}

void Dot1Q::priority(small_uint<3> new_priority) {
    header_.priority = new_priority;
}

void Dot1Q::cfi(small_uint<1> new_cfi) {
    header_.cfi = new_cfi;
}

void Dot1Q::id(small_uint<12> new_id) {
    #if TINS_IS_LITTLE_ENDIAN
    header_.idL = new_id & 0xff;
    header_.idH = new_id >> 8;
    #else
    header_.id = new_id;
    #endif
}

void Dot1Q::payload_type(uint16_t new_type) {
    header_.type = Endian::host_to_be(new_type);
}

uint32_t Dot1Q::header_size() const {
    return sizeof(header_);
}

uint32_t Dot1Q::trailer_size() const {
    if (append_padding_) {
        uint32_t total_size = sizeof(header_);
        if (inner_pdu()) {
            total_size += inner_pdu()->size();
        }
        return (total_size > 50) ? 0 : (50 - total_size);
    }
    else {
        return 0;
    }
}

void Dot1Q::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    OutputMemoryStream stream(buffer, total_sz);
    if (inner_pdu()) {
        Constants::Ethernet::e flag;
        PDUType type = inner_pdu()->pdu_type();
        if (type == PDU::DOT1Q) {
            flag = Constants::Ethernet::QINQ;
        }
        else {
            // Set the appropriate payload type flag
            flag = Internals::pdu_flag_to_ether_type(type);
        }
        if (flag != Constants::Ethernet::UNKNOWN) {
            payload_type(static_cast<uint16_t>(flag));
        }
    }
    else {
        payload_type(0);
    }
    stream.write(header_);

    // Skip inner PDU size
    if (inner_pdu()) {
        stream.skip(inner_pdu()->size());
    }
    // Write trailer
    stream.fill(trailer_size(), 0);
}

#if TINS_IS_LITTLE_ENDIAN
    uint16_t Dot1Q::get_id(const dot1q_header* hdr) {
        return hdr->idL | (hdr->idH << 8);
    }
#else
    uint16_t Dot1Q::get_id(const dot1q_header* hdr) {
        return hdr->id;
    }
#endif

void Dot1Q::append_padding(bool value) {
    append_padding_ = value;
}

bool Dot1Q::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(header_)) {
        return false;
    }
    const dot1q_header* dot1q_ptr = (const dot1q_header*)ptr;
    if (get_id(dot1q_ptr) == get_id(&header_)) {
        ptr += sizeof(header_);
        total_sz -= sizeof(header_);
        return inner_pdu() ? inner_pdu()->matches_response(ptr, total_sz) : true;
    }
    return false;

}

} // Tins
