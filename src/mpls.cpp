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

#include "mpls.h"
#include "ip.h"
#include "ipv6.h"
#include "rawpdu.h"
#include "memory_helpers.h"
#include "icmp_extension.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

MPLS::MPLS() : header_() {

}

MPLS::MPLS(const ICMPExtension& extension) {
    InputMemoryStream stream(extension.payload());
    stream.read(header_);
}

MPLS::MPLS(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    if (stream) {
        // If this is the last MPLS, then construct an IP
        if (bottom_of_stack()) {
            uint8_t version = (*stream.pointer() >> 4) & 0x0f;
            if (version == 4) {
                inner_pdu(new Tins::IP(stream.pointer(), stream.size()));
            }
            else if (version == 6) {
                inner_pdu(new Tins::IPv6(stream.pointer(), stream.size()));
            }
            else {
                inner_pdu(new Tins::RawPDU(stream.pointer(), stream.size()));
            }
        }
        else {
            inner_pdu(new MPLS(stream.pointer(), stream.size()));
        }
    }
}

void MPLS::label(small_uint<20> value) {
    const uint32_t label_value = value;
    const uint16_t label_high = Endian::host_to_be<uint16_t>(label_value >> 4);
    const uint8_t label_low = (label_value << 4) & 0xf0;
    header_.label_high = label_high & 0xffff;
    header_.label_low_and_bottom = (header_.label_low_and_bottom & 0x0f) | label_low;
}

void MPLS::bottom_of_stack(small_uint<1> value) {
    header_.label_low_and_bottom = (header_.label_low_and_bottom & 0xfe) | value;
}

void MPLS::ttl(uint8_t value) {
    header_.ttl = value;
}

uint32_t MPLS::header_size() const {
    return sizeof(header_);
}

void MPLS::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent) {
    OutputMemoryStream stream(buffer, total_sz);
    // If we have a parent PDU, we might set the bottom-of-stack field
    if (parent) {
        // We'll set it if we either don't have a child or we have one and it's not MPLS
        if (!inner_pdu() || inner_pdu()->pdu_type() != PDU::MPLS) {
            bottom_of_stack(1);
        }
    }
    stream.write(header_);
}

} // Tins
