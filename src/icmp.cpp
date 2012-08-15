/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdexcept>
#include <cstring>
#include <cassert>
#ifndef WIN32
    #include <netinet/in.h>
#endif
#include "icmp.h"
#include "rawpdu.h"
#include "utils.h"

uint16_t Tins::ICMP::global_id = 0, Tins::ICMP::global_seq = 0;


Tins::ICMP::ICMP(Flags flag) : PDU(IPPROTO_ICMP) {
    std::memset(&_icmp, 0, sizeof(icmphdr));
    switch(flag) {
        case ECHO_REPLY:
            break;
        case ECHO_REQUEST:
            set_echo_request();
            break;
        case DEST_UNREACHABLE:
            set_dest_unreachable();
            break;
        default:
            break;
    };
}

Tins::ICMP::ICMP(const uint8_t *buffer, uint32_t total_sz) : PDU(IPPROTO_ICMP) {
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
    _icmp.check = Utils::to_be(new_check);
}

void Tins::ICMP::id(uint16_t new_id) {
    _icmp.un.echo.id = Utils::to_be(new_id);
}

void Tins::ICMP::sequence(uint16_t new_seq) {
    _icmp.un.echo.sequence = Utils::to_be(new_seq);
}

void Tins::ICMP::gateway(uint32_t new_gw) {
    _icmp.un.gateway = Utils::to_be(new_gw);
}

void Tins::ICMP::mtu(uint16_t new_mtu) {
    _icmp.un.frag.mtu = Utils::to_be(new_mtu);
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

void Tins::ICMP::set_echo_request() {
    set_echo_request(global_id++, global_seq++);
    if(global_id == 0xffff)
        global_id = 0;
    if(global_seq == 0xffff)
        global_seq = 0;
}

void Tins::ICMP::set_echo_reply(uint16_t id, uint16_t seq) {
    type(ECHO_REPLY);
    this->id(id);
    sequence(seq);
}

void Tins::ICMP::set_echo_reply() {
    set_echo_reply(global_id++, global_seq++);
    if(global_id == 0xffff)
        global_id = 0;
    if(global_seq == 0xffff)
        global_seq = 0;
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
        _icmp.check = Utils::to_be<uint16_t>(~checksum);
    }
    memcpy(buffer, &_icmp, sizeof(icmphdr));
    _icmp.check = 0;
}

bool Tins::ICMP::matches_response(uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(icmphdr))
        return false;
    icmphdr *icmp_ptr = (icmphdr*)ptr;
    if(_icmp.type == ECHO_REQUEST) {
        return icmp_ptr->type == ECHO_REPLY && icmp_ptr->un.echo.id == _icmp.un.echo.id && icmp_ptr->un.echo.sequence == _icmp.un.echo.sequence;
    }
    return false;
}

Tins::PDU *Tins::ICMP::clone_packet(const uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(icmphdr))
        return 0;
    PDU *child = 0, *cloned;
    if(total_sz > sizeof(icmphdr)) {
        if((child = PDU::clone_inner_pdu(ptr + sizeof(icmphdr), total_sz - sizeof(icmphdr))) == 0)
            return 0;
    }
    cloned = new ICMP(ptr, std::min(total_sz, (uint32_t)sizeof(_icmp)));
    cloned->inner_pdu(child);
    return cloned;
}
