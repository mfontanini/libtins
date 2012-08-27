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
BootP::BootP() 
: PDU(255), _vend(64) {
    std::memset(&_bootp, 0, sizeof(bootphdr));
}

BootP::BootP(const uint8_t *buffer, uint32_t total_sz, uint32_t vend_field_size) 
: PDU(255), _vend(vend_field_size) 
{
    if(total_sz < sizeof(bootphdr) + vend_field_size)
        throw std::runtime_error("Not enough size for a BootP header in the buffer.");
    std::memcpy(&_bootp, buffer, sizeof(bootphdr));
    buffer += sizeof(bootphdr);
    total_sz -= sizeof(bootphdr);
    _vend.assign(buffer, buffer + vend_field_size);
    // Maybe RawPDU on what is left on the buffer?...
}

uint32_t BootP::header_size() const {
    return sizeof(bootphdr) + _vend.size();
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
    _bootp.xid = Utils::host_to_be(new_xid);
}

void BootP::secs(uint16_t new_secs) {
    _bootp.secs = Utils::host_to_be(new_secs);
}

void BootP::padding(uint16_t new_padding) {
    _bootp.padding = Utils::host_to_be(new_padding);
}

void BootP::ciaddr(ipaddress_type new_ciaddr) {
    _bootp.ciaddr = new_ciaddr;
}

void BootP::yiaddr(ipaddress_type new_yiaddr) {
    _bootp.yiaddr = new_yiaddr;
}

void BootP::siaddr(ipaddress_type new_siaddr) {
    _bootp.siaddr = new_siaddr;
}

void BootP::giaddr(ipaddress_type new_giaddr) {
    _bootp.giaddr = new_giaddr;
}

void BootP::sname(const uint8_t *new_sname) {
    std::memcpy(_bootp.sname, new_sname, sizeof(_bootp.sname));
}

void BootP::file(const uint8_t *new_file) {
    std::memcpy(_bootp.file, new_file, sizeof(_bootp.file));
}

void BootP::vend(const vend_type &new_vend) {
    _vend = new_vend;
}

void BootP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(bootphdr) + _vend.size());
    std::memcpy(buffer, &_bootp, sizeof(bootphdr));
    std::copy(_vend.begin(), _vend.end(), buffer + sizeof(bootphdr));
}
}
