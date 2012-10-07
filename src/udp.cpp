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
#include <cassert>
#include <cstring>
#include "udp.h"
#include "constants.h"
#include "utils.h"
#include "ip.h"
#include "rawpdu.h"

Tins::UDP::UDP(uint16_t dport, uint16_t sport, PDU *child) 
: PDU(child) 
{
    this->dport(dport);
    this->sport(sport);
    _udp.check = 0;
    _udp.len = 0;
}

Tins::UDP::UDP(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(udphdr))
        throw std::runtime_error("Not enough size for an UDP header in the buffer.");
    std::memcpy(&_udp, buffer, sizeof(udphdr));
    total_sz -= sizeof(udphdr);
    if(total_sz)
        inner_pdu(new RawPDU(buffer + sizeof(udphdr), total_sz));
}

void Tins::UDP::dport(uint16_t new_dport) {
    _udp.dport = Endian::host_to_be(new_dport);
}

void Tins::UDP::sport(uint16_t new_sport) {
    _udp.sport = Endian::host_to_be(new_sport);
}

void Tins::UDP::length(uint16_t new_len) {
    _udp.len = Endian::host_to_be(new_len);
}

uint32_t Tins::UDP::header_size() const {
    return sizeof(udphdr);
}

void Tins::UDP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(udphdr));
    const Tins::IP *ip_packet = dynamic_cast<const Tins::IP*>(parent);
    if(inner_pdu())
        length(sizeof(udphdr) + inner_pdu()->size());
    std::memcpy(buffer, &_udp, sizeof(udphdr));
    if(!_udp.check && ip_packet) {
        uint32_t checksum = Utils::pseudoheader_checksum(ip_packet->src_addr(), ip_packet->dst_addr(), size(), Constants::IP::PROTO_UDP) +
                            Utils::do_checksum(buffer, buffer + total_sz);
        while (checksum >> 16)
            checksum = (checksum & 0xffff)+(checksum >> 16);
        ((udphdr*)buffer)->check = Endian::host_to_be<uint16_t>(~checksum);
    }
    _udp.check = 0;
}

void Tins::UDP::copy_fields(const UDP *other) {
    std::memcpy(&_udp, &other->_udp, sizeof(_udp));
}
