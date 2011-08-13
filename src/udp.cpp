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

#ifndef WIN32
    #include <netinet/in.h>
#endif
#include <cassert>
#include <cstring>
#include "utils.h"
#include "udp.h"
#include "ip.h"
#include "rawpdu.h"

Tins::UDP::UDP(uint16_t sport, uint16_t dport) : PDU(IPPROTO_UDP) {
    _udp.sport = sport;
    _udp.dport = dport;
    _udp.check = 0;
    _udp.len = 0;
}

void Tins::UDP::payload(uint8_t *new_payload, uint32_t new_payload_size) {
    inner_pdu(new RawPDU(new_payload, new_payload_size));
    _udp.len = Utils::net_to_host_s(sizeof(udphdr) + new_payload_size);
}

void Tins::UDP::dport(uint16_t new_dport) {
    _udp.dport = new_dport;
}
         
void Tins::UDP::sport(uint16_t new_sport) {
    _udp.sport = new_sport;
}

uint32_t Tins::UDP::header_size() const {
    return sizeof(udphdr);
}

void Tins::UDP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(udphdr));
    const IP *ip_packet = dynamic_cast<const IP*>(parent);
    if(!_udp.check && ip_packet) {
        uint32_t checksum = PDU::pseudoheader_checksum(ip_packet->source_address(), ip_packet->dest_address(), size(), IPPROTO_UDP) + 
                            PDU::do_checksum(buffer + sizeof(udphdr), buffer + total_sz) + PDU::do_checksum((uint8_t*)&_udp, ((uint8_t*)&_udp) + sizeof(udphdr));
        while (checksum >> 16)
            checksum = (checksum & 0xffff)+(checksum >> 16);
        _udp.check = Utils::net_to_host_s(~checksum);
    }
    std::memcpy(buffer, &_udp, sizeof(udphdr));
}

