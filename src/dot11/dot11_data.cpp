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

#include "dot11/dot11_data.h"
#ifdef HAVE_DOT11

#include <cstring>
#include <cassert>
#include "rawpdu.h"
#include "snap.h"
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {
/* Dot11Data */

Dot11Data::Dot11Data(const uint8_t *buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz)
{
    const uint32_t offset = init(buffer, total_sz);
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(offset);
    if (stream) {
        // If the wep bit is on, then just use a RawPDU
        if(wep()) {
            inner_pdu(new Tins::RawPDU(stream.pointer(), stream.size()));
        }
        else {
            inner_pdu(new Tins::SNAP(stream.pointer(), stream.size()));
        }
    }
}

Dot11Data::Dot11Data(const uint8_t *buffer, uint32_t total_sz, no_inner_pdu) 
: Dot11(buffer, total_sz)
{
    init(buffer, total_sz);
}

uint32_t Dot11Data::init(const uint8_t *buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(Dot11::header_size());
    stream.read(_ext_header);
    if (from_ds() && to_ds()) {
        stream.read(_addr4);
    }
    return total_sz - stream.size();
}

Dot11Data::Dot11Data(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11(dst_hw_addr) 
{
    type(Dot11::DATA);
    memset(&_ext_header, 0, sizeof(_ext_header));
    addr2(src_hw_addr);
}

uint32_t Dot11Data::header_size() const {
    uint32_t sz = Dot11::header_size() + sizeof(_ext_header);
    if (this->from_ds() && this->to_ds())
        sz += 6;
    return sz;
}

void Dot11Data::addr2(const address_type &new_addr2) {
    std::copy(new_addr2.begin(), new_addr2.end(), _ext_header.addr2);
}

void Dot11Data::addr3(const address_type &new_addr3) {
    std::copy(new_addr3.begin(), new_addr3.end(), _ext_header.addr3);
}

void Dot11Data::frag_num(small_uint<4> new_frag_num) {
    #if TINS_IS_LITTLE_ENDIAN
    _ext_header.frag_seq = new_frag_num | (_ext_header.frag_seq & 0xfff0);
    #else
    _ext_header.frag_seq = (new_frag_num << 8) | (_ext_header.frag_seq & 0xf0ff);
    #endif
}

void Dot11Data::seq_num(small_uint<12> new_seq_num) {
    #if TINS_IS_LITTLE_ENDIAN
    _ext_header.frag_seq = (new_seq_num << 4) | (_ext_header.frag_seq & 0xf);
    #else
    _ext_header.frag_seq = Endian::host_to_le<uint16_t>(new_seq_num << 4) | (_ext_header.frag_seq & 0xf00);
    #endif
}

void Dot11Data::addr4(const address_type &new_addr4) {
    _addr4 = new_addr4;
}

void Dot11Data::write_ext_header(OutputMemoryStream& stream) {
    stream.write(_ext_header);
    if (from_ds() && to_ds()) {
        stream.write(_addr4);
    }
}

/* QoS data. */

Dot11QoSData::Dot11QoSData(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11Data(dst_hw_addr, src_hw_addr) 
{
    subtype(Dot11::QOS_DATA_DATA);
    _qos_control = 0;
}

Dot11QoSData::Dot11QoSData(const uint8_t *buffer, uint32_t total_sz) 
// Am I breaking something? :S
: Dot11Data(buffer, total_sz, no_inner_pdu()) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(data_frame_size());
    stream.read(_qos_control);
    if (total_sz) {
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
    this->_qos_control = Endian::host_to_le(new_qos_control);
}

uint32_t Dot11QoSData::header_size() const {
    return Dot11Data::header_size() + sizeof(this->_qos_control);
}

void Dot11QoSData::write_fixed_parameters(OutputMemoryStream& stream) {
    stream.write(_qos_control);
}
} // namespace Tins

#endif // HAVE_DOT11
