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

#include "dot11/dot11_control.h"
#ifdef TINS_HAVE_DOT11

#include <algorithm>
#include "memory_helpers.h"

using std::copy;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

// Dot11Control

Dot11Control::Dot11Control(const address_type& dst_addr) 
: Dot11(dst_addr) {
    type(CONTROL);
}

Dot11Control::Dot11Control(const uint8_t* buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz) {

}

// Dot11ControlTA

Dot11ControlTA::Dot11ControlTA(const address_type& dst_addr, 
                               const address_type& target_address) 
: Dot11Control(dst_addr) {
    target_addr(target_address);
}

Dot11ControlTA::Dot11ControlTA(const uint8_t* buffer, uint32_t total_sz) : Dot11Control(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(sizeof(dot11_header));
    stream.read(taddr_);
}

uint32_t Dot11ControlTA::header_size() const {
    return Dot11::header_size() + taddr_.size();
}

void Dot11ControlTA::write_ext_header(OutputMemoryStream& stream) {
    stream.write(taddr_);
}

void Dot11ControlTA::target_addr(const address_type& addr) {
    taddr_ = addr;
}

// Dot11RTS

Dot11RTS::Dot11RTS(const address_type& dst_addr, 
                   const address_type& target_addr) 
: Dot11ControlTA(dst_addr, target_addr) {
    subtype(RTS);
}

Dot11RTS::Dot11RTS(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

// Dot11PSPoll

Dot11PSPoll::Dot11PSPoll(const address_type& dst_addr, 
                         const address_type& target_addr) 
: Dot11ControlTA(dst_addr, target_addr) {
    subtype(PS);
}

Dot11PSPoll::Dot11PSPoll(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

// Dot11CFEnd

Dot11CFEnd::Dot11CFEnd(const address_type& dst_addr, 
                       const address_type& target_addr) 
: Dot11ControlTA(dst_addr, target_addr) {
    subtype(CF_END);
}

Dot11CFEnd::Dot11CFEnd(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

// Dot11EndCFAck

Dot11EndCFAck::Dot11EndCFAck(const address_type& dst_addr, 
                             const address_type& target_addr) 
: Dot11ControlTA(dst_addr, target_addr) {
    subtype(CF_END_ACK);
}

Dot11EndCFAck::Dot11EndCFAck(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

// Dot11Ack

Dot11Ack::Dot11Ack(const address_type& dst_addr) 
: Dot11Control(dst_addr) {
    subtype(ACK);
}

Dot11Ack::Dot11Ack(const uint8_t* buffer, uint32_t total_sz) 
: Dot11Control(buffer, total_sz) {

}

// Dot11BlockAck

Dot11BlockAckRequest::Dot11BlockAckRequest(const address_type& dst_addr, 
                                           const address_type& target_addr)
: Dot11ControlTA(dst_addr, target_addr), bar_control_(0), start_sequence_(0) {
    subtype(BLOCK_ACK_REQ);
}

Dot11BlockAckRequest::Dot11BlockAckRequest(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(controlta_size());
    stream.read(bar_control_);
    stream.read(start_sequence_);
}

void Dot11BlockAckRequest::write_ext_header(OutputMemoryStream& stream) {
    Dot11ControlTA::write_ext_header(stream);
    stream.write(bar_control_);
    stream.write(start_sequence_);
}

void Dot11BlockAckRequest::bar_control(small_uint<4> bar) {
    #if TINS_IS_LITTLE_ENDIAN
    bar_control_ = bar | (bar_control_ & 0xfff0);
    #else
    bar_control_ = (bar << 8) | (bar_control_ & 0xf0ff);
    #endif
}

void Dot11BlockAckRequest::start_sequence(small_uint<12> seq) {
    #if TINS_IS_LITTLE_ENDIAN
    start_sequence_ = (seq << 4) | (start_sequence_ & 0xf);
    #else
    start_sequence_ = Endian::host_to_le<uint16_t>(seq << 4) | (start_sequence_ & 0xf00);
    #endif
}

void Dot11BlockAckRequest::fragment_number(small_uint<4> frag) {
    #if TINS_IS_LITTLE_ENDIAN
    start_sequence_ = frag | (start_sequence_ & 0xfff0);
    #else
    start_sequence_ = (frag << 8) | (start_sequence_ & 0xf0ff);
    #endif
}

uint32_t Dot11BlockAckRequest::header_size() const {
    return Dot11ControlTA::header_size() + sizeof(start_sequence_) + sizeof(start_sequence_);
}

// Dot11BlockAck

Dot11BlockAck::Dot11BlockAck(const address_type& dst_addr, 
                             const address_type& target_addr)
: Dot11ControlTA(dst_addr, target_addr), bar_control_(0), start_sequence_(0), bitmap_() {
    subtype(BLOCK_ACK);
}

Dot11BlockAck::Dot11BlockAck(const uint8_t* buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(controlta_size());
    stream.read(bar_control_);
    stream.read(start_sequence_);
    stream.read(bitmap_);
}

void Dot11BlockAck::bar_control(small_uint<4> bar) {
    #if TINS_IS_LITTLE_ENDIAN
    bar_control_ = bar | (bar_control_ & 0xfff0);
    #else
    bar_control_ = (bar << 8) | (bar_control_ & 0xf0ff);
    #endif
}

void Dot11BlockAck::start_sequence(small_uint<12> seq) {
    #if TINS_IS_LITTLE_ENDIAN
    start_sequence_ = (seq << 4) | (start_sequence_ & 0xf);
    #else
    start_sequence_ = Endian::host_to_le<uint16_t>(seq << 4) | (start_sequence_ & 0xf00);
    #endif
}

void Dot11BlockAck::fragment_number(small_uint<4> frag) {
    #if TINS_IS_LITTLE_ENDIAN
    start_sequence_ = frag | (start_sequence_ & 0xfff0);
    #else
    start_sequence_ = (frag << 8) | (start_sequence_ & 0xf0ff);
    #endif
}

void Dot11BlockAck::bitmap(const uint8_t* bit) {
    copy(bit, bit + bitmap_size, bitmap_);
}

void Dot11BlockAck::write_ext_header(OutputMemoryStream& stream) {
    Dot11ControlTA::write_ext_header(stream);
    stream.write(bar_control_);
    stream.write(start_sequence_);
    stream.write(bitmap_);
}

uint32_t Dot11BlockAck::header_size() const {
    return Dot11ControlTA::header_size() + sizeof(start_sequence_) + 
           sizeof(start_sequence_) + sizeof(bitmap_);
}

} // Tins

#endif // TINS_HAVE_DOT11
