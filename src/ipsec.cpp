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
#include "ipsec.h"
#include "internals.h"
#include "rawpdu.h"
#include "memory_helpers.h"

using std::memcpy;
using std::copy;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

IPSecAH::IPSecAH() 
: header_(), icv_(4) {
    length(2);
}

IPSecAH::IPSecAH(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    const uint32_t ah_len = 4 * (static_cast<uint16_t>(length()) + 2);
    if (ah_len < sizeof(header_)) {
        throw malformed_packet();
    }
    const uint32_t icv_length = ah_len - sizeof(header_);
    if (!stream.can_read(icv_length)) {
        throw malformed_packet();
    }
    stream.read(icv_, icv_length);
    if (stream) {
        inner_pdu(
            Internals::pdu_from_flag(
                static_cast<Constants::IP::e>(next_header()),
                stream.pointer(), 
                stream.size(), 
                true
            )
        );
    }
}

void IPSecAH::next_header(uint8_t new_next_header) {
    header_.next_header = new_next_header;
}

void IPSecAH::length(uint8_t new_length) {
    header_.length = new_length;
}

void IPSecAH::spi(uint32_t new_spi) {
    header_.spi = Endian::host_to_be(new_spi);
}

void IPSecAH::seq_number(uint32_t new_seq_number) {
    header_.seq_number = Endian::host_to_be(new_seq_number);
}

void IPSecAH::icv(const byte_array& newicv_) {
    icv_ = newicv_;
}

uint32_t IPSecAH::header_size() const {
    return static_cast<uint32_t>(sizeof(header_) + icv_.size());
}

void IPSecAH::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    if (inner_pdu()) {
        next_header(Internals::pdu_flag_to_ip_type(inner_pdu()->pdu_type()));
    }
    length(header_size() / sizeof(uint32_t) - 2);
    OutputMemoryStream output(buffer, total_sz);
    output.write(header_);
    output.write(icv_.begin(), icv_.end());
}

// IPSecESP

IPSecESP::IPSecESP() 
: header_() {

}

IPSecESP::IPSecESP(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    if (stream) {
        inner_pdu(new RawPDU(stream.pointer(), stream.size()));
    }
}

void IPSecESP::spi(uint32_t new_spi) {
    header_.spi = Endian::host_to_be(new_spi);
}

void IPSecESP::seq_number(uint32_t new_seq_number) {
    header_.seq_number = Endian::host_to_be(new_seq_number);
}

uint32_t IPSecESP::header_size() const {
    return sizeof(header_);
}

void IPSecESP::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    OutputMemoryStream output(buffer, total_sz);
    output.write(header_);
}

} // Tins
