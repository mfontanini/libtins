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

#include "dot11/dot11_control.h"
#ifdef HAVE_DOT11

#include <cstring>
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {
 /* Dot11Control */

Dot11Control::Dot11Control(const address_type &dst_addr) 
: Dot11(dst_addr) 
{
    type(CONTROL);
}

Dot11Control::Dot11Control(const uint8_t *buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz) {

}

/* Dot11ControlTA */

Dot11ControlTA::Dot11ControlTA(const address_type &dst_addr, 
  const address_type &target_address) 
: Dot11Control(dst_addr)
{
    target_addr(target_address);
}

Dot11ControlTA::Dot11ControlTA(const uint8_t *buffer, uint32_t total_sz) : Dot11Control(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(sizeof(ieee80211_header));
    stream.read(_taddr);
}

uint32_t Dot11ControlTA::header_size() const {
    return Dot11::header_size() + sizeof(_taddr);
}

void Dot11ControlTA::write_ext_header(OutputMemoryStream& stream) {
    stream.write(_taddr);
}

void Dot11ControlTA::target_addr(const address_type &addr) {
    _taddr = addr;
}

/* Dot11RTS */

Dot11RTS::Dot11RTS(const address_type &dst_addr, 
  const address_type &target_addr) 
: Dot11ControlTA(dst_addr, target_addr) 
{
    subtype(RTS);
}

Dot11RTS::Dot11RTS(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

/* Dot11PSPoll */

Dot11PSPoll::Dot11PSPoll(const address_type &dst_addr, 
  const address_type &target_addr) 
: Dot11ControlTA(dst_addr, target_addr) 
{
    subtype(PS);
}

Dot11PSPoll::Dot11PSPoll(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

/* Dot11CFEnd */

Dot11CFEnd::Dot11CFEnd(const address_type &dst_addr, 
  const address_type &target_addr) 
: Dot11ControlTA(dst_addr, target_addr) 
{
    subtype(CF_END);
}

Dot11CFEnd::Dot11CFEnd(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

/* Dot11EndCFAck */

Dot11EndCFAck::Dot11EndCFAck(const address_type &dst_addr, 
  const address_type &target_addr) 
: Dot11ControlTA(dst_addr, target_addr) 
{
    subtype(CF_END_ACK);
}

Dot11EndCFAck::Dot11EndCFAck(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

/* Dot11Ack */

Dot11Ack::Dot11Ack(const address_type &dst_addr) 
: Dot11Control(dst_addr) 
{
    subtype(ACK);
}

Dot11Ack::Dot11Ack(const uint8_t *buffer, uint32_t total_sz) 
: Dot11Control(buffer, total_sz)
{

}

/* Dot11BlockAck */

Dot11BlockAckRequest::Dot11BlockAckRequest(const address_type &dst_addr, 
  const address_type &target_addr)
: Dot11ControlTA(dst_addr, target_addr) 
{
    init_block_ack();
}

Dot11BlockAckRequest::Dot11BlockAckRequest(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) 
{
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(controlta_size());
    stream.read(_bar_control);
    stream.read(_start_sequence);
}

void Dot11BlockAckRequest::init_block_ack() {
    subtype(BLOCK_ACK_REQ);
    std::memset(&_bar_control, 0, sizeof(_bar_control));
    std::memset(&_start_sequence, 0, sizeof(_start_sequence));
}

void Dot11BlockAckRequest::write_ext_header(OutputMemoryStream& stream) {
    Dot11ControlTA::write_ext_header(stream);
    stream.write(_bar_control);
    stream.write(_start_sequence);
}

void Dot11BlockAckRequest::bar_control(small_uint<4> bar) {
    #if TINS_IS_LITTLE_ENDIAN
    _bar_control = bar | (_bar_control & 0xfff0);
    #else
    _bar_control = (bar << 8) | (_bar_control & 0xf0ff);
    #endif
}

void Dot11BlockAckRequest::start_sequence(small_uint<12> seq) {
    #if TINS_IS_LITTLE_ENDIAN
    _start_sequence = (seq << 4) | (_start_sequence & 0xf);
    #else
    _start_sequence = Endian::host_to_le<uint16_t>(seq << 4) | (_start_sequence & 0xf00);
    #endif
}

void Dot11BlockAckRequest::fragment_number(small_uint<4> frag) {
    #if TINS_IS_LITTLE_ENDIAN
    _start_sequence = frag | (_start_sequence & 0xfff0);
    #else
    _start_sequence = (frag << 8) | (_start_sequence & 0xf0ff);
    #endif
}

uint32_t Dot11BlockAckRequest::header_size() const {
    return Dot11ControlTA::header_size() + sizeof(_start_sequence) + sizeof(_start_sequence);
}

/* Dot11BlockAck */

Dot11BlockAck::Dot11BlockAck(const address_type &dst_addr, 
  const address_type &target_addr)
: Dot11ControlTA(dst_addr, target_addr) 
{
    subtype(BLOCK_ACK);
    std::memset(_bitmap, 0, sizeof(_bitmap));
}

Dot11BlockAck::Dot11BlockAck(const uint8_t *buffer, uint32_t total_sz) : Dot11ControlTA(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(controlta_size());
    stream.read(_bar_control);
    stream.read(_start_sequence);
    stream.read(_bitmap);
}

void Dot11BlockAck::bar_control(small_uint<4> bar) {
    #if TINS_IS_LITTLE_ENDIAN
    _bar_control = bar | (_bar_control & 0xfff0);
    #else
    _bar_control = (bar << 8) | (_bar_control & 0xf0ff);
    #endif
}

void Dot11BlockAck::start_sequence(small_uint<12> seq) {
    #if TINS_IS_LITTLE_ENDIAN
    _start_sequence = (seq << 4) | (_start_sequence & 0xf);
    #else
    _start_sequence = Endian::host_to_le<uint16_t>(seq << 4) | (_start_sequence & 0xf00);
    #endif
}

void Dot11BlockAck::fragment_number(small_uint<4> frag) {
    #if TINS_IS_LITTLE_ENDIAN
    _start_sequence = frag | (_start_sequence & 0xfff0);
    #else
    _start_sequence = (frag << 8) | (_start_sequence & 0xf0ff);
    #endif
}

void Dot11BlockAck::bitmap(const uint8_t *bit) {
    std::memcpy(_bitmap, bit, sizeof(_bitmap));
}

void Dot11BlockAck::write_ext_header(OutputMemoryStream& stream) {
    Dot11ControlTA::write_ext_header(stream);
    stream.write(_bar_control);
    stream.write(_start_sequence);
    stream.write(_bitmap);
}

uint32_t Dot11BlockAck::header_size() const {
    return Dot11ControlTA::header_size() + sizeof(_start_sequence) + sizeof(_start_sequence) + sizeof(_bitmap);
}
} // namespace Tins

#endif // HAVE_DOT11
