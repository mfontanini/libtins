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
#include "bootp.h"

namespace Tins{
BootP::BootP() : PDU(255), _vend_size(64) {
    _vend = new uint8_t[64];
    std::memset(&_bootp, 0, sizeof(bootphdr));
    std::memset(_vend, 0, 64);
}

BootP::BootP(const uint8_t *buffer, uint32_t total_sz, uint32_t vend_field_size) 
: PDU(255), _vend(0), _vend_size(vend_field_size) 
{
    if(total_sz < sizeof(bootphdr) + vend_field_size)
        throw std::runtime_error("Not enough size for a BootP header in the buffer.");
    std::memcpy(&_bootp, buffer, sizeof(bootphdr));
    buffer += sizeof(bootphdr);
    total_sz -= sizeof(bootphdr);
    if(_vend_size) {
        _vend = new uint8_t[_vend_size];
        std::copy(buffer, buffer + _vend_size, _vend);
    }
    // Maybe RawPDU on what is left on the buffer?...
}

BootP::BootP(const BootP &other) : PDU(other) {
    copy_bootp_fields(&other);
}

BootP &BootP::operator= (const BootP &other) {
    copy_bootp_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

BootP::~BootP() {
    delete[] _vend;
}

uint32_t BootP::header_size() const {
    return sizeof(bootphdr) + _vend_size;
}

void BootP::opcode(uint8_t new_opcode) {
    _bootp.opcode = new_opcode;
}

void BootP::htype(uint8_t new_htype) {
    _bootp.htype = new_htype;
}

void BootP::hlen(uint8_t new_hlen) {
    _bootp.hlen = new_hlen;
}

void BootP::hops(uint8_t new_hops) {
    _bootp.hops = new_hops;
}

void BootP::xid(uint32_t new_xid) {
    _bootp.xid = Utils::net_to_host_l(new_xid);
}

void BootP::secs(uint16_t new_secs) {
    _bootp.secs = Utils::net_to_host_s(new_secs);
}

void BootP::padding(uint16_t new_padding) {
    _bootp.padding = Utils::net_to_host_s(new_padding);
}

void BootP::ciaddr(IPv4Address new_ciaddr) {
    _bootp.ciaddr = new_ciaddr;
}

void BootP::yiaddr(IPv4Address new_yiaddr) {
    _bootp.yiaddr = new_yiaddr;
}

void BootP::siaddr(IPv4Address new_siaddr) {
    _bootp.siaddr = new_siaddr;
}

void BootP::giaddr(IPv4Address new_giaddr) {
    _bootp.giaddr = new_giaddr;
}

void BootP::sname(const uint8_t *new_sname) {
    std::memcpy(_bootp.sname, new_sname, sizeof(_bootp.sname));
}

void BootP::file(const uint8_t *new_file) {
    std::memcpy(_bootp.file, new_file, sizeof(_bootp.file));
}

void BootP::vend(uint8_t *new_vend, uint32_t size) {
    delete[] _vend;
    _vend_size = size;
    _vend = new uint8_t[size];
    std::copy(new_vend, new_vend + size, _vend);
}

void BootP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(bootphdr) + _vend_size);
    std::memcpy(buffer, &_bootp, sizeof(bootphdr));
    //std::memcpy(buffer + sizeof(bootphdr), _vend, _vend_size);
    std::copy(_vend, _vend + _vend_size, buffer + sizeof(bootphdr));
}

void BootP::copy_bootp_fields(const BootP *other) {
    std::memcpy(&_bootp, &other->_bootp, sizeof(_bootp));
    _vend_size = other->_vend_size;
    if(_vend_size) {
        _vend = new uint8_t[_vend_size];
        std::memcpy(_vend, other->_vend, _vend_size);
    }
    else
        _vend = 0;
}
}
