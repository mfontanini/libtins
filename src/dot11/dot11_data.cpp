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

#include "dot11/dot11_data.h"
#ifdef TINS_HAVE_DOT11

#include <cstring>
#include "rawpdu.h"
#include "snap.h"
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

// Dot11Data

Dot11Data::Dot11Data(const uint8_t* buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz) {
    const uint32_t offset = init(buffer, total_sz);
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(offset);
    if (stream) {
        // If the wep bit is on, then just use a RawPDU
        if (wep()) {
            inner_pdu(new Tins::RawPDU(stream.pointer(), stream.size()));
        }
        else {
            inner_pdu(new Tins::SNAP(stream.pointer(), stream.size()));
        }
    }
}

Dot11Data::Dot11Data(const uint8_t* buffer, uint32_t total_sz, no_inner_pdu) 
: Dot11(buffer, total_sz) {
    init(buffer, total_sz);
}

uint32_t Dot11Data::init(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(Dot11::header_size());
    stream.read(ext_header_);
    if (from_ds() && to_ds()) {
        stream.read(addr4_);
    }
    return total_sz - stream.size();
}

Dot11Data::Dot11Data(const address_type& dst_hw_addr, 
                     const address_type& src_hw_addr) 
: Dot11(dst_hw_addr), ext_header_() {
    type(Dot11::DATA);
    addr2(src_hw_addr);
}

uint32_t Dot11Data::header_size() const {
    uint32_t sz = Dot11::header_size() + sizeof(ext_header_);
    if (this->from_ds() && this->to_ds()) {
        sz += 6;
    }
    return sz;
}

void Dot11Data::addr2(const address_type& new_addr2) {
    new_addr2.copy(ext_header_.addr2);
}

void Dot11Data::addr3(const address_type& new_addr3) {
    new_addr3.copy(ext_header_.addr3);
}

void Dot11Data::frag_num(small_uint<4> new_frag_num) {
    #if TINS_IS_LITTLE_ENDIAN
    ext_header_.frag_seq = new_frag_num | (ext_header_.frag_seq & 0xfff0);
    #else
    ext_header_.frag_seq = (new_frag_num << 8) | (ext_header_.frag_seq & 0xf0ff);
    #endif
}

void Dot11Data::seq_num(small_uint<12> new_seq_num) {
    #if TINS_IS_LITTLE_ENDIAN
    ext_header_.frag_seq = (new_seq_num << 4) | (ext_header_.frag_seq & 0xf);
    #else
    ext_header_.frag_seq = Endian::host_to_le<uint16_t>(new_seq_num << 4) | (ext_header_.frag_seq & 0xf00);
    #endif
}

void Dot11Data::addr4(const address_type& new_addr4) {
    addr4_ = new_addr4;
}

void Dot11Data::write_ext_header(OutputMemoryStream& stream) {
    stream.write(ext_header_);
    if (from_ds() && to_ds()) {
        stream.write(addr4_);
    }
}

// QoS data

Dot11QoSData::Dot11QoSData(const address_type& dst_hw_addr, 
                           const address_type& src_hw_addr) 
: Dot11Data(dst_hw_addr, src_hw_addr), qos_control_() {
    subtype(Dot11::QOS_DATA_DATA);
}

Dot11QoSData::Dot11QoSData(const uint8_t* buffer, uint32_t total_sz) 
: Dot11Data(buffer, total_sz, no_inner_pdu()) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(Dot11Data::header_size());
    stream.read(qos_control_);
    if (stream) {
        // If the wep bit is on, then just use a RawPDU
        if (wep()) {
            inner_pdu(new Tins::RawPDU(stream.pointer(), stream.size()));
        }
        else {
            inner_pdu(new Tins::SNAP(stream.pointer(), stream.size()));
        }
    }
}

void Dot11QoSData::qos_control(uint16_t new_qos_control) {
    qos_control_ = Endian::host_to_le(new_qos_control);
}

uint32_t Dot11QoSData::header_size() const {
    return Dot11Data::header_size() + sizeof(qos_control_);
}

void Dot11QoSData::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(qos_control_);
}

} // Tins

#endif // TINS_HAVE_DOT11
