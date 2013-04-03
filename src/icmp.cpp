/*
 * Copyright (c) 2012, Nasel
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
#include <cassert>
#ifndef WIN32
    #define NOMINMAX
    #include <netinet/in.h>
#endif
#include "icmp.h"
#include "rawpdu.h"
#include "utils.h"

Tins::ICMP::ICMP(Flags flag) 
{
    std::memset(&_icmp, 0, sizeof(icmphdr));
    type(flag);
}

Tins::ICMP::ICMP(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(icmphdr))
        throw std::runtime_error("Not enough size for an ICMP header in the buffer.");
    std::memcpy(&_icmp, buffer, sizeof(icmphdr));
    total_sz -= sizeof(icmphdr);
    if(total_sz)
        inner_pdu(new RawPDU(buffer + sizeof(icmphdr), total_sz));
}

void Tins::ICMP::code(uint8_t new_code) {
    _icmp.code = new_code;
}

void Tins::ICMP::type(Flags new_type) {
    _icmp.type = new_type;
}

void Tins::ICMP::check(uint16_t new_check) {
    _icmp.check = Endian::host_to_be(new_check);
}

void Tins::ICMP::id(uint16_t new_id) {
    _icmp.un.echo.id = Endian::host_to_be(new_id);
}

void Tins::ICMP::sequence(uint16_t new_seq) {
    _icmp.un.echo.sequence = Endian::host_to_be(new_seq);
}

void Tins::ICMP::gateway(uint32_t new_gw) {
    _icmp.un.gateway = Endian::host_to_be(new_gw);
}

void Tins::ICMP::mtu(uint16_t new_mtu) {
    _icmp.un.frag.mtu = Endian::host_to_be(new_mtu);
}

void Tins::ICMP::pointer(uint8_t new_pointer) {
    _icmp.un.pointer = new_pointer;
}

uint32_t Tins::ICMP::header_size() const {
    return sizeof(icmphdr);
}

void Tins::ICMP::set_echo_request(uint16_t id, uint16_t seq) {
    type(ECHO_REQUEST);
    this->id(id);
    sequence(seq);
}

void Tins::ICMP::set_echo_reply(uint16_t id, uint16_t seq) {
    type(ECHO_REPLY);
    this->id(id);
    sequence(seq);
}

void Tins::ICMP::set_info_request(uint16_t id, uint16_t seq) {
    type(INFO_REQUEST);
    code(0);
    this->id(id);
    sequence(seq);
}

void Tins::ICMP::set_info_reply(uint16_t id, uint16_t seq) {
    type(INFO_REPLY);
    code(0);
    this->id(id);
    sequence(seq);
}

void Tins::ICMP::set_dest_unreachable() {
    type(DEST_UNREACHABLE);
}

void Tins::ICMP::set_time_exceeded(bool ttl_exceeded) {
    type(TIME_EXCEEDED);
    code((ttl_exceeded) ? 0 : 1);
}

void Tins::ICMP::set_param_problem(bool set_pointer, uint8_t bad_octet) {
    type(PARAM_PROBLEM);
    if(set_pointer) {
        code(0);
        pointer(bad_octet);
    }
    else
        code(1);
}

void Tins::ICMP::set_source_quench() {
    type(SOURCE_QUENCH);
}

void Tins::ICMP::set_redirect(uint8_t icode, uint32_t address) {
    type(REDIRECT);
    code(icode);
    gateway(address);
}

void Tins::ICMP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    assert(total_sz >= sizeof(icmphdr));
    if(!_icmp.check) {
        uint32_t checksum = Utils::do_checksum(buffer + sizeof(icmphdr), buffer + total_sz) + 
                            Utils::do_checksum((uint8_t*)&_icmp, ((uint8_t*)&_icmp) + sizeof(icmphdr));
        while (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16);
        _icmp.check = Endian::host_to_be<uint16_t>(~checksum);
    }
    memcpy(buffer, &_icmp, sizeof(icmphdr));
    _icmp.check = 0;
}

bool Tins::ICMP::matches_response(uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(icmphdr))
        return false;
    const icmphdr *icmp_ptr = (const icmphdr*)ptr;
    if(_icmp.type == ECHO_REQUEST && icmp_ptr->type == ECHO_REPLY) {
        return icmp_ptr->un.echo.id == _icmp.un.echo.id && icmp_ptr->un.echo.sequence == _icmp.un.echo.sequence;
    }
    return false;
}

Tins::PDU *Tins::ICMP::clone_packet(const uint8_t *ptr, uint32_t total_sz) {
    return new ICMP(ptr, total_sz);
}
