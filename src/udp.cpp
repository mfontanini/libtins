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
#ifdef TINS_DEBUG
    #include <cassert>
#endif
#include <cstring>
#include "udp.h"
#include "constants.h"
#include "utils.h"
#include "ip.h"
#include "ipv6.h"
#include "rawpdu.h"
#include "exceptions.h"

namespace Tins {
UDP::UDP(uint16_t dport, uint16_t sport) 
{
    this->dport(dport);
    this->sport(sport);
    _udp.check = 0;
    _udp.len = 0;
}

UDP::UDP(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(udphdr))
        throw malformed_packet();
    std::memcpy(&_udp, buffer, sizeof(udphdr));
    total_sz -= sizeof(udphdr);
    if(total_sz)
        inner_pdu(new RawPDU(buffer + sizeof(udphdr), total_sz));
}

void UDP::dport(uint16_t new_dport) {
    _udp.dport = Endian::host_to_be(new_dport);
}

void UDP::sport(uint16_t new_sport) {
    _udp.sport = Endian::host_to_be(new_sport);
}

void UDP::length(uint16_t new_len) {
    _udp.len = Endian::host_to_be(new_len);
}

uint32_t UDP::header_size() const {
    return sizeof(udphdr);
}

void UDP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    #ifdef TINS_DEBUG
    assert(total_sz >= sizeof(udphdr));
    #endif
    _udp.check = 0;
    if(inner_pdu())
        length(sizeof(udphdr) + inner_pdu()->size());
    else
        length(sizeof(udphdr));
    std::memcpy(buffer, &_udp, sizeof(udphdr));
    const Tins::IP *ip_packet = tins_cast<const Tins::IP*>(parent);
    if(ip_packet) {
        uint32_t checksum = Utils::pseudoheader_checksum(
                                ip_packet->src_addr(), 
                                ip_packet->dst_addr(), 
                                size(), 
                                Constants::IP::PROTO_UDP
                            ) + Utils::do_checksum(buffer, buffer + total_sz);
        while (checksum >> 16)
            checksum = (checksum & 0xffff)+(checksum >> 16);
        _udp.check = Endian::host_to_be<uint16_t>(~checksum);
        ((udphdr*)buffer)->check = _udp.check;
    }
    else {
        const Tins::IPv6 *ip6_packet = tins_cast<const Tins::IPv6*>(parent);
        if(ip6_packet) {
            uint32_t checksum = Utils::pseudoheader_checksum(
                        ip6_packet->src_addr(), 
                        ip6_packet->dst_addr(), 
                        size(), 
                        Constants::IP::PROTO_UDP
                    ) + Utils::do_checksum(buffer, buffer + total_sz);
            while (checksum >> 16)
                checksum = (checksum & 0xffff)+(checksum >> 16);
            _udp.check = Endian::host_to_be<uint16_t>(~checksum);
            ((udphdr*)buffer)->check = _udp.check;
        }
    }
}

bool UDP::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(total_sz < sizeof(udphdr))
        return false;
    const udphdr *udp_ptr = (const udphdr*)ptr;
    if(udp_ptr->sport == _udp.dport && udp_ptr->dport == _udp.sport) {
        return inner_pdu() 
                ? 
                inner_pdu()->matches_response(
                    ptr + sizeof(udphdr), 
                    total_sz - sizeof(udphdr)
                ) 
                : 
                0;
    }
    return false;
}

}
