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

#include <cstring>
#include <cassert>
#ifndef WIN32
    #include <netinet/in.h>
    #include <sys/socket.h>
#else
    #include <ws2tcpip.h>
#endif
#include <iostream> //borrame
#include "ipv6.h"
#include "constants.h"
#include "packet_sender.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "icmpv6.h"
#include "rawpdu.h"

namespace Tins {

IPv6::IPv6(address_type ip_dst, address_type ip_src, PDU *child) 
: headers_size(0)
{
    std::memset(&_header, 0, sizeof(_header));
    version(6);
    dst_addr(ip_dst);
    src_addr(ip_src);
}

IPv6::IPv6(const uint8_t *buffer, uint32_t total_sz) 
: headers_size(0) {
    if(total_sz < sizeof(_header))
        throw std::runtime_error("Not enough size for an IPv6 PDU");
    std::memcpy(&_header, buffer, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    uint8_t current_header = _header.next_header;
    while(total_sz) {
        if(is_extension_header(current_header)) {
            if(total_sz < 8)
                throw header_size_error();
            // every ext header is at least 8 bytes long
            // minus one, from the next_header field.
            uint32_t size = static_cast<uint32_t>(buffer[1]) + 8;
            // -1 -> next header identifier
            if(total_sz < size) 
                throw header_size_error();
            // minus one, from the size field
            add_ext_header(
                ipv6_ext_header(buffer[0], size - sizeof(uint8_t)*2, buffer + 2)
            );
            current_header = buffer[0];
            buffer += size;
            total_sz -= size;
        }
        else {
            switch(current_header) {
                case Constants::IP::PROTO_TCP:
                    inner_pdu(new Tins::TCP(buffer, total_sz));
                    break;
                case Constants::IP::PROTO_UDP:
                    inner_pdu(new Tins::UDP(buffer, total_sz));
                    break;
                case Constants::IP::PROTO_ICMP:
                    inner_pdu(new Tins::ICMP(buffer, total_sz));
                    break;
                case Constants::IP::PROTO_ICMPV6:
                    inner_pdu(new Tins::ICMPv6(buffer, total_sz));
                    break;
                default:
                    inner_pdu(new Tins::RawPDU(buffer, total_sz));
                    break;
            }
            total_sz = 0;
        }
    }
}

bool IPv6::is_extension_header(uint8_t header_id) {
    return header_id == HOP_BY_HOP || header_id == DESTINATION_ROUTING_OPTIONS
        || header_id == ROUTING || header_id == FRAGMENT || header_id == AUTHENTICATION
        || header_id == SECURITY_ENCAPSULATION || header_id == DESTINATION_OPTIONS
        || header_id == MOBILITY || header_id == NO_NEXT_HEADER;
}

void IPv6::version(small_uint<4> new_version) {
    _header.version = new_version;
}

void IPv6::traffic_class(uint8_t new_traffic_class) {
    #if TINS_IS_LITTLE_ENDIAN
    _header.traffic_class = (new_traffic_class >> 4) & 0xf;
    _header.flow_label[0] = (_header.flow_label[0] & 0x0f) | ((new_traffic_class << 4) & 0xf0);
    #else
    _header.traffic_class = new_traffic_class;
    #endif
}

void IPv6::flow_label(small_uint<20> new_flow_label) {
    #if TINS_IS_LITTLE_ENDIAN
    uint32_t value = Endian::host_to_be<uint32_t>(new_flow_label);
    _header.flow_label[2] = (value >> 24) & 0xff;
    _header.flow_label[1] = (value >> 16) & 0xff;
    _header.flow_label[0] = ((value >> 8) & 0x0f) | (_header.flow_label[0] & 0xf0);
    #else
    _header.flow_label = new_flow_label;
    #endif
}

void IPv6::payload_length(uint16_t new_payload_length) {
    _header.payload_length = Endian::host_to_be(new_payload_length);
}

void IPv6::next_header(uint8_t new_next_header) {
    _header.next_header = new_next_header;
}

void IPv6::hop_limit(uint8_t new_hop_limit) {
    _header.hop_limit = new_hop_limit;
}

void IPv6::src_addr(const address_type &new_src_addr) {
    new_src_addr.copy(_header.src_addr);
}

void IPv6::dst_addr(const address_type &new_dst_addr) {
    new_dst_addr.copy(_header.dst_addr);
}

uint32_t IPv6::header_size() const {
    return sizeof(_header) + headers_size;
}

void IPv6::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    #ifdef DEBUG
    assert(total_sz >= header_size());
    #endif
    if(inner_pdu()) {
        uint8_t new_flag = 0xff;
        switch(inner_pdu()->pdu_type()) {
            case PDU::IP:
                new_flag = Constants::IP::PROTO_IPIP;
                break;
            case PDU::TCP:
                new_flag = Constants::IP::PROTO_TCP;
                break;
            case PDU::UDP:
                new_flag = Constants::IP::PROTO_UDP;
                break;
            case PDU::ICMP:
                new_flag = Constants::IP::PROTO_ICMP;
                break;
            case PDU::ICMPv6:
                new_flag = Constants::IP::PROTO_ICMPV6;
                break;
            default:
                break;
        };
        if(new_flag != 0xff)
            set_last_next_header(new_flag);
    }
    payload_length(total_sz - sizeof(_header));
    std::memcpy(buffer, &_header, sizeof(_header));
    buffer += sizeof(_header);
    for(headers_type::const_iterator it = ext_headers.begin(); it != ext_headers.end(); ++it) {
        buffer = write_header(*it, buffer);
    }
}

#ifndef BSD
void IPv6::send(PacketSender &sender) {
    struct sockaddr_in6 link_addr;
    PacketSender::SocketType type = PacketSender::IPV6_SOCKET;
    link_addr.sin6_family = AF_INET6;
    link_addr.sin6_port = 0;
    std::copy(_header.dst_addr, _header.dst_addr + address_type::address_size, (uint8_t*)&link_addr.sin6_addr);
    if(inner_pdu() && inner_pdu()->pdu_type() == PDU::ICMP)
        type = PacketSender::ICMP_SOCKET;

    sender.send_l3(*this, (struct sockaddr*)&link_addr, sizeof(link_addr), type);
}
#endif

void IPv6::add_ext_header(const ipv6_ext_header &header) {
    ext_headers.push_back(header);
    headers_size += header.data_size() + sizeof(uint8_t) * 2;
}

const IPv6::ipv6_ext_header *IPv6::search_header(ExtensionHeader id) const {
    uint8_t current_header = _header.next_header;
    headers_type::const_iterator it = ext_headers.begin();
    while(it != ext_headers.end() && current_header != id) {
        current_header = it->option();
        ++it;
    }
    if(it == ext_headers.end())
        return 0;
    return &*it;
}

void IPv6::set_last_next_header(uint8_t value) {
    if(ext_headers.empty())
        _header.next_header = value;
    else 
        ext_headers.back().option(value);
}

uint8_t *IPv6::write_header(const ipv6_ext_header &header, uint8_t *buffer) {
    *buffer++ = header.option();
    *buffer++ = (header.data_size() > 8) ? (header.data_size() - 8) : 0;
    return std::copy(header.data_ptr(), header.data_ptr() + header.data_size(), buffer);
}

}
