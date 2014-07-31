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

#include <stdexcept>
#include <cstring>
#ifdef TINS_DEBUG
#include <cassert>
#endif
#ifndef WIN32
    #include <netinet/in.h>
#endif
#include "rawpdu.h"
#include "utils.h"
#include "exceptions.h"
#include "icmp.h"

namespace Tins {
ICMP::ICMP(Flags flag) 
: _orig_timestamp_or_address_mask(), _recv_timestamp(), _trans_timestamp()
{
    std::memset(&_icmp, 0, sizeof(icmphdr));
    type(flag);
}

ICMP::ICMP(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(icmphdr))
        throw malformed_packet();
    std::memcpy(&_icmp, buffer, sizeof(icmphdr));
    buffer += sizeof(icmphdr);
    total_sz -= sizeof(icmphdr);
    uint32_t uint32_t_buffer = 0;
    if(type() == TIMESTAMP_REQUEST || type() == TIMESTAMP_REPLY) {
        if(total_sz < sizeof(uint32_t) * 3)
            throw malformed_packet();
        memcpy(&uint32_t_buffer, buffer, sizeof(uint32_t));
        original_timestamp(uint32_t_buffer);
        memcpy(&uint32_t_buffer, buffer + sizeof(uint32_t), sizeof(uint32_t));
        receive_timestamp(uint32_t_buffer);
        memcpy(&uint32_t_buffer, buffer + 2 * sizeof(uint32_t), sizeof(uint32_t));
        transmit_timestamp(uint32_t_buffer);
        total_sz -= sizeof(uint32_t) * 3;
        buffer += sizeof(uint32_t) * 3;
    }
    else if(type() == ADDRESS_MASK_REQUEST || type() == ADDRESS_MASK_REPLY) {
        if(total_sz < sizeof(uint32_t))
            throw malformed_packet();
        memcpy(&uint32_t_buffer, buffer, sizeof(uint32_t));
        address_mask(address_type(uint32_t_buffer));
        total_sz -= sizeof(uint32_t);
        buffer += sizeof(uint32_t);
    }
    if(total_sz)
        inner_pdu(new RawPDU(buffer, total_sz));
}

void ICMP::code(uint8_t new_code) {
    _icmp.code = new_code;
}

void ICMP::type(Flags new_type) {
    _icmp.type = new_type;
}

void ICMP::checksum(uint16_t new_check) {
    _icmp.check = Endian::host_to_be(new_check);
}

void ICMP::id(uint16_t new_id) {
    _icmp.un.echo.id = Endian::host_to_be(new_id);
}

void ICMP::sequence(uint16_t new_seq) {
    _icmp.un.echo.sequence = Endian::host_to_be(new_seq);
}

void ICMP::gateway(address_type new_gw) {
    _icmp.un.gateway = Endian::host_to_be(static_cast<uint32_t>(new_gw));
}

void ICMP::mtu(uint16_t new_mtu) {
    _icmp.un.frag.mtu = Endian::host_to_be(new_mtu);
}

void ICMP::pointer(uint8_t new_pointer) {
    _icmp.un.pointer = new_pointer;
}

void ICMP::original_timestamp(uint32_t new_timestamp) {
    _orig_timestamp_or_address_mask = Endian::host_to_be(new_timestamp);
}

void ICMP::receive_timestamp(uint32_t new_timestamp) {
    _recv_timestamp = Endian::host_to_be(new_timestamp);
}

void ICMP::transmit_timestamp(uint32_t new_timestamp) {
    _trans_timestamp = Endian::host_to_be(new_timestamp);
}

void ICMP::address_mask(address_type new_mask) {
    _orig_timestamp_or_address_mask = Endian::host_to_be(static_cast<uint32_t>(new_mask));
}

uint32_t ICMP::header_size() const {
    uint32_t extra = 0;
    if(type() == TIMESTAMP_REQUEST || type() == TIMESTAMP_REPLY) 
        extra = sizeof(uint32_t) * 3;
    else if(type() == ADDRESS_MASK_REQUEST || type() == ADDRESS_MASK_REPLY) 
        extra = sizeof(uint32_t);
    return sizeof(icmphdr) + extra;
}

void ICMP::set_echo_request(uint16_t id, uint16_t seq) {
    type(ECHO_REQUEST);
    this->id(id);
    sequence(seq);
}

void ICMP::set_echo_reply(uint16_t id, uint16_t seq) {
    type(ECHO_REPLY);
    this->id(id);
    sequence(seq);
}

void ICMP::set_info_request(uint16_t id, uint16_t seq) {
    type(INFO_REQUEST);
    code(0);
    this->id(id);
    sequence(seq);
}

void ICMP::set_info_reply(uint16_t id, uint16_t seq) {
    type(INFO_REPLY);
    code(0);
    this->id(id);
    sequence(seq);
}

void ICMP::set_dest_unreachable() {
    type(DEST_UNREACHABLE);
}

void ICMP::set_time_exceeded(bool ttl_exceeded) {
    type(TIME_EXCEEDED);
    code((ttl_exceeded) ? 0 : 1);
}

void ICMP::set_param_problem(bool set_pointer, uint8_t bad_octet) {
    type(PARAM_PROBLEM);
    if(set_pointer) {
        code(0);
        pointer(bad_octet);
    }
    else
        code(1);
}

void ICMP::set_source_quench() {
    type(SOURCE_QUENCH);
}

void ICMP::set_redirect(uint8_t icode, address_type address) {
    type(REDIRECT);
    code(icode);
    gateway(address);
}

void ICMP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    #ifdef TINS_DEBUG
    assert(total_sz >= sizeof(icmphdr));
    #endif

    uint32_t uint32_t_buffer;
    if(type() == TIMESTAMP_REQUEST || type() == TIMESTAMP_REPLY) {
        uint32_t_buffer = original_timestamp();
        memcpy(buffer + sizeof(icmphdr), &uint32_t_buffer, sizeof(uint32_t));
        uint32_t_buffer = receive_timestamp();
        memcpy(buffer + sizeof(icmphdr) + sizeof(uint32_t), &uint32_t_buffer, sizeof(uint32_t));
        uint32_t_buffer = transmit_timestamp();
        memcpy(buffer + sizeof(icmphdr) + 2 * sizeof(uint32_t), &uint32_t_buffer, sizeof(uint32_t));
    }
    else if(type() == ADDRESS_MASK_REQUEST || type() == ADDRESS_MASK_REPLY) {
        uint32_t_buffer = address_mask();
        memcpy(buffer + sizeof(icmphdr), &uint32_t_buffer, sizeof(uint32_t));
    }
    // checksum calc
    _icmp.check = 0;
    memcpy(buffer, &_icmp, sizeof(icmphdr));
    uint32_t checksum = Utils::do_checksum(buffer, buffer + total_sz);

    while (checksum >> 16)
        checksum = (checksum & 0xffff) + (checksum >> 16);

    _icmp.check = Endian::host_to_be<uint16_t>(~checksum);
    memcpy(buffer + 2, &_icmp.check, sizeof(uint16_t));
}

bool ICMP::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(total_sz < sizeof(icmphdr))
        return false;
    const icmphdr *icmp_ptr = (const icmphdr*)ptr;
    if((_icmp.type == ECHO_REQUEST && icmp_ptr->type == ECHO_REPLY) || 
        (_icmp.type == TIMESTAMP_REQUEST && icmp_ptr->type == TIMESTAMP_REPLY) ||
        (_icmp.type == ADDRESS_MASK_REQUEST && icmp_ptr->type == ADDRESS_MASK_REPLY)) {
        return icmp_ptr->un.echo.id == _icmp.un.echo.id && icmp_ptr->un.echo.sequence == _icmp.un.echo.sequence;
    }
    return false;
}
} // namespace Tins
