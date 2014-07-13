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
#include <cassert>
#include "bootp.h"
#include "exceptions.h"

namespace Tins{
BootP::BootP() 
: _vend(64) {
    std::memset(&_bootp, 0, sizeof(bootphdr));
}

BootP::BootP(const uint8_t *buffer, uint32_t total_sz, uint32_t vend_field_size) 
: _vend(vend_field_size) 
{
    if(total_sz < sizeof(bootphdr) + vend_field_size)
        throw malformed_packet();
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
    _bootp.xid = Endian::host_to_be(new_xid);
}

void BootP::secs(uint16_t new_secs) {
    _bootp.secs = Endian::host_to_be(new_secs);
}

void BootP::padding(uint16_t new_padding) {
    _bootp.padding = Endian::host_to_be(new_padding);
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
    //std::memcpy(_bootp.sname, new_sname, sizeof(_bootp.sname));
    std::copy(new_sname, new_sname + sizeof(_bootp.sname), _bootp.sname);
}

void BootP::file(const uint8_t *new_file) {
    //std::memcpy(_bootp.file, new_file, sizeof(_bootp.file));
    std::copy(new_file, new_file + sizeof(_bootp.file), _bootp.file);
}

void BootP::vend(const vend_type &new_vend) {
    _vend = new_vend;
}

void BootP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    #ifdef TINS_DEBUG
    assert(total_sz >= sizeof(bootphdr) + _vend.size());
    #endif
    std::memcpy(buffer, &_bootp, sizeof(bootphdr));
    std::copy(_vend.begin(), _vend.end(), buffer + sizeof(bootphdr));
}

bool BootP::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(total_sz < sizeof(bootphdr))
        return false;
    const bootphdr *bootp_ptr = (const bootphdr *)ptr;
    return bootp_ptr->xid == _bootp.xid;
}
}
