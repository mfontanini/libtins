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
#include <cassert>
#include <cstring>
#include "udp.h"
#include "constants.h"
#include "ip.h"
#include "rawpdu.h"

Tins::UDP::UDP(uint16_t dport, uint16_t sport, PDU *child) : PDU(Constants::IP::PROTO_UDP, child) {
    this->dport(dport);
    this->sport(sport);
    _udp.check = 0;
    _udp.len = 0;
}

Tins::UDP::UDP(const uint8_t *buffer, uint32_t total_sz) : PDU(Constants::IP::PROTO_UDP) {
    if(total_sz < sizeof(udphdr))
        throw std::runtime_error("Not enough size for an UDP header in the buffer.");
    std::memcpy(&_udp, buffer, sizeof(udphdr));
    total_sz -= sizeof(udphdr);
    if(total_sz)
        inner_pdu(new RawPDU(buffer + sizeof(udphdr), total_sz));
}

void Tins::UDP::payload(uint8_t *new_payload, uint32_t new_payload_size) {
    inner_pdu(new RawPDU(new_payload, new_payload_size));
}

void Tins::UDP::dport(uint16_t new_dport) {
    _udp.dport = Utils::net_to_host_s(new_dport);
}

void Tins::UDP::sport(uint16_t new_sport) {
    _udp.sport = Utils::net_to_host_s(new_sport);
}

void Tins::UDP::length(uint16_t new_len) {
    _udp.len = Utils::net_to_host_s(new_len);
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
        ((udphdr*)buffer)->check = Utils::net_to_host_s(~checksum);
    }
    _udp.check = 0;
}

void Tins::UDP::copy_fields(const UDP *other) {
    std::memcpy(&_udp, &other->_udp, sizeof(_udp));
}
