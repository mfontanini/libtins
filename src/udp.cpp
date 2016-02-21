/*
 * Copyright (c) 2016, Matias Fontanini
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
#include "udp.h"
#include "constants.h"
#include "utils.h"
#include "ip.h"
#include "ipv6.h"
#include "rawpdu.h"
#include "exceptions.h"
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PDU::metadata UDP::extract_metadata(const uint8_t *buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(udp_header))) {
        throw malformed_packet();
    }
    return metadata(sizeof(udp_header), pdu_flag, PDU::UNKNOWN);
}

UDP::UDP(uint16_t dport, uint16_t sport)
: header_() {
    this->dport(dport);
    this->sport(sport);
}

UDP::UDP(const uint8_t* buffer, uint32_t total_sz)  {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    if (stream) {
        inner_pdu(new RawPDU(stream.pointer(), stream.size()));
    }
}

void UDP::dport(uint16_t new_dport) {
    header_.dport = Endian::host_to_be(new_dport);
}

void UDP::sport(uint16_t new_sport) {
    header_.sport = Endian::host_to_be(new_sport);
}

void UDP::length(uint16_t new_len) {
    header_.len = Endian::host_to_be(new_len);
}

uint32_t UDP::header_size() const {
    return sizeof(udp_header);
}

uint32_t sum_range(const uint8_t* start, const uint8_t* end) {
    uint32_t checksum(0);
    const uint8_t* last = end;
    uint16_t buffer = 0;
    uint16_t padding = 0;
    const uint8_t* ptr = start;

    if (((end - start) & 1) == 1) {
        last = end - 1;
        padding = Endian::host_to_le<uint16_t>(*(end - 1));
    }

    while (ptr < last) {
        memcpy(&buffer, ptr, sizeof(uint16_t));
        checksum += buffer;
        ptr += sizeof(uint16_t);
    }

    checksum += padding;
    return checksum;  
}

uint32_t pseudoheader_checksum(IPv4Address source_ip, IPv4Address dest_ip, uint32_t len, uint32_t flag) {
    uint32_t checksum(0);
    uint8_t buffer[sizeof(uint32_t) * 3];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write(source_ip);
    stream.write(dest_ip);
    stream.write(Endian::host_to_be<uint16_t>(flag));
    stream.write(Endian::host_to_be<uint16_t>(len));
    uint16_t* ptr = (uint16_t*)buffer, *end = (uint16_t*)(buffer + sizeof(buffer));
    while (ptr < end) {
        checksum += *ptr++;
    }
    return checksum;
}

void UDP::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent) {
    OutputMemoryStream stream(buffer, total_sz);
    // Set checksum to 0, we'll calculate it at the end
    header_.check = 0;
    if (inner_pdu()) {
        length(static_cast<uint16_t>(sizeof(udp_header) + inner_pdu()->size()));
    }
    else {
        length(static_cast<uint16_t>(sizeof(udp_header)));
    }
    stream.write(header_);
    uint32_t checksum = 0;
    if (const Tins::IP* ip_packet = tins_cast<const Tins::IP*>(parent)) {
        checksum = Utils::pseudoheader_checksum(
            ip_packet->src_addr(), 
            ip_packet->dst_addr(), 
            size(), 
            Constants::IP::PROTO_UDP
        ) + Utils::sum_range(buffer, buffer + total_sz);
    }
    else if (const Tins::IPv6* ip6_packet = tins_cast<const Tins::IPv6*>(parent)) {
        checksum = Utils::pseudoheader_checksum(
            ip6_packet->src_addr(), 
            ip6_packet->dst_addr(), 
            size(), 
            Constants::IP::PROTO_UDP
        ) + Utils::sum_range(buffer, buffer + total_sz);
    }
    else {
        return;
    }
    while (checksum >> 16) {
        checksum = (checksum & 0xffff)+(checksum >> 16);
    }
    header_.check = ~checksum;
    // If checksum is 0, it has to be set to 0xffff
    header_.check = (header_.check == 0) ? 0xffff : header_.check;
    ((udp_header*)buffer)->check = header_.check;
}

bool UDP::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(udp_header)) {
        return false;
    }
    const udp_header* udp_ptr = (const udp_header*)ptr;
    if (udp_ptr->sport == header_.dport && udp_ptr->dport == header_.sport) {
        if (inner_pdu()) { 
            return inner_pdu()->matches_response(
                ptr + sizeof(udp_header), 
                total_sz - sizeof(udp_header)
            );
        }
        else {
            return 0;
        }
    }
    return false;
}

} // Tins
