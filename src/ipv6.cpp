/*
 * Copyright (c) 2017, Matias Fontanini
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
#ifndef _WIN32
    #include <netinet/in.h>
    #include <sys/socket.h>
#else
    #include <ws2tcpip.h>
#endif
#include <tins/ipv6.h>
#include <tins/constants.h>
#include <tins/packet_sender.h>
#include <tins/rawpdu.h>
#include <tins/exceptions.h>
#include <tins/pdu_allocator.h>
#include <tins/memory_helpers.h>
#include <tins/detail/pdu_helpers.h>

using std::make_pair;
using std::vector;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PDU::metadata IPv6::extract_metadata(const uint8_t *buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(ipv6_header))) {
        throw malformed_packet();
    }
    InputMemoryStream stream(buffer, total_sz);
    const ipv6_header* header = (const ipv6_header*)buffer;
    uint32_t header_size = sizeof(ipv6_header);
    uint8_t current_header = header->next_header;
    stream.skip(sizeof(ipv6_header));
    while (is_extension_header(current_header)) {
        current_header = stream.read<uint8_t>();
        const uint32_t ext_size = (static_cast<uint32_t>(stream.read<uint8_t>()) + 1) * 8;
        const uint32_t payload_size = ext_size - sizeof(uint8_t) * 2;
        header_size += ext_size;
        stream.skip(payload_size);
    }
    return metadata(header_size, pdu_flag, PDU::UNKNOWN);
}

IPv6::hop_by_hop_header IPv6::hop_by_hop_header::from_extension_header(const ext_header& hdr) {
    if (TINS_UNLIKELY(hdr.option() != HOP_BY_HOP)) {
        throw invalid_ipv6_extension_header();
    }
    hop_by_hop_header header;
    header.options = parse_header_options(hdr.data_ptr(), hdr.data_size());
    return header;
}

IPv6::destination_routing_header IPv6::destination_routing_header::from_extension_header(const ext_header& hdr) {
    if (TINS_UNLIKELY(hdr.option() != DESTINATION_ROUTING_OPTIONS)) {
        throw invalid_ipv6_extension_header();
    }
    destination_routing_header header;
    header.options = parse_header_options(hdr.data_ptr(), hdr.data_size());
    return header;
}

IPv6::routing_header IPv6::routing_header::from_extension_header(const ext_header& hdr) {
    if (TINS_UNLIKELY(hdr.option() != ROUTING)) {
        throw invalid_ipv6_extension_header();
    }
    Memory::InputMemoryStream stream(hdr.data_ptr(), hdr.data_size());
    routing_header header;
    header.routing_type = stream.read<uint8_t>();
    header.segments_left = stream.read<uint8_t>();
    header.data.assign(stream.pointer(), stream.pointer() + stream.size());
    return header;
}

IPv6::fragment_header IPv6::fragment_header::from_extension_header(const ext_header& hdr) {
    if (TINS_UNLIKELY(hdr.option() != FRAGMENT)) {
        throw invalid_ipv6_extension_header();
    }
    Memory::InputMemoryStream stream(hdr.data_ptr(), hdr.data_size());
    fragment_header header;
    uint16_t field = stream.read_be<uint16_t>();
    header.fragment_offset = field >> 3;
    header.more_fragments = field & 1;
    header.identification = stream.read_be<uint32_t>();
    return header;
}

IPv6::IPv6(address_type ip_dst, address_type ip_src, PDU* /*child*/)
: header_(), next_header_() {
    version(6);
    dst_addr(ip_dst);
    src_addr(ip_src);
}

IPv6::IPv6(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    uint8_t current_header = header_.next_header;
    uint32_t actual_payload_length = payload_length();
    bool is_payload_fragmented = false;
    while (stream) {
        if (is_extension_header(current_header)) {
            if (current_header == FRAGMENT) {
                is_payload_fragmented = true;
            }
            const uint8_t ext_type = stream.read<uint8_t>();
            // every ext header is at least 8 bytes long
            // minus one, from the next_header field.
            const uint32_t ext_size = (static_cast<uint32_t>(stream.read<uint8_t>()) + 1) * 8;
            const uint32_t payload_size = ext_size - sizeof(uint8_t) * 2;
            if (!stream.can_read(payload_size)) {
                throw malformed_packet();
            }
            // Add a header using the current header type (e.g. what we saw as the next
            // header type in the previous)
            add_header(ext_header(current_header, payload_size, stream.pointer()));
            if (actual_payload_length == 0u && current_header == HOP_BY_HOP) {
                // could be a jumbogram, look for Jumbo Payload Option
                InputMemoryStream options(stream.pointer(), payload_size);
                while (options) {
                    const uint8_t opt_type = options.read<uint8_t>();
                    if (opt_type == PAD_1) {
                        continue;
                    }
                    const uint8_t opt_size = options.read<uint8_t>();
                    if (opt_type == JUMBO_PAYLOAD) {
                        if (opt_size != 4) {
                            throw malformed_packet();
                        }
                        actual_payload_length = stream.read_be<uint32_t>();
                        break;
                    }
                    options.skip(opt_size);
                }
            }
            current_header = ext_type;
            actual_payload_length -= ext_size;
            stream.skip(payload_size);
        }
        else {
            if (!stream.can_read(actual_payload_length)) {
                throw malformed_packet();
            }
            if (is_payload_fragmented) {
                inner_pdu(new Tins::RawPDU(stream.pointer(), actual_payload_length));
            }
            else {
                inner_pdu(
                    Internals::pdu_from_flag(
                        static_cast<Constants::IP::e>(current_header),
                        stream.pointer(), 
                        actual_payload_length,
                        false
                    )
                );
                if (!inner_pdu()) {
                    inner_pdu(
                        Internals::allocate<IPv6>(
                            current_header,
                            stream.pointer(), 
                            actual_payload_length
                        )
                    );
                    if (!inner_pdu()) {
                        inner_pdu(new Tins::RawPDU(stream.pointer(), actual_payload_length));
                    }
                }
            }
            // We got to an actual PDU, we're done
            break;
        }
    }
    next_header_ = current_header;
}

bool IPv6::is_extension_header(uint8_t header_id) {
    return header_id == HOP_BY_HOP || header_id == DESTINATION_ROUTING_OPTIONS
        || header_id == ROUTING || header_id == FRAGMENT || header_id == AUTHENTICATION
        || header_id == DESTINATION_OPTIONS || header_id == MOBILITY
        || header_id == NO_NEXT_HEADER;
}

uint32_t IPv6::get_padding_size(const ext_header& header) {
    const uint32_t padding = (header.data_size() + sizeof(uint8_t) * 2) % 8;
    return padding == 0 ? 0 : (8 - padding);
}

vector<IPv6::header_option_type> IPv6::parse_header_options(const uint8_t* data, size_t size) {
    Memory::InputMemoryStream stream(data, size);
    vector<header_option_type> options;

    while (stream.size() > 0) {
        try {
            uint8_t option = stream.read<uint8_t>();
            if (option == PAD_1) {
                continue;
            }
            uint8_t size = stream.read<uint8_t>();
            if (size > stream.size()) {
                throw invalid_ipv6_extension_header();
            }
            if (option != PAD_N) {
                options.push_back(make_pair(option, vector<uint8_t>(stream.pointer(),
                                                                    stream.pointer() +
                                                                    size)));
            }
            stream.skip(size);
        } catch (const malformed_packet&) {
            throw invalid_ipv6_extension_header();
        }
    }
    return options;
}

void IPv6::version(small_uint<4> new_version) {
    header_.version = new_version;
}

void IPv6::traffic_class(uint8_t new_traffic_class) {
    #if TINS_IS_LITTLE_ENDIAN
    header_.traffic_class = (new_traffic_class >> 4) & 0xf;
    header_.flow_label[0] = (header_.flow_label[0] & 0x0f) | ((new_traffic_class << 4) & 0xf0);
    #else
    header_.traffic_class = new_traffic_class;
    #endif
}

void IPv6::flow_label(small_uint<20> new_flow_label) {
    #if TINS_IS_LITTLE_ENDIAN
    uint32_t value = Endian::host_to_be<uint32_t>(new_flow_label);
    header_.flow_label[2] = (value >> 24) & 0xff;
    header_.flow_label[1] = (value >> 16) & 0xff;
    header_.flow_label[0] = ((value >> 8) & 0x0f) | (header_.flow_label[0] & 0xf0);
    #else
    header_.flow_label = new_flow_label;
    #endif
}

void IPv6::payload_length(uint16_t new_payload_length) {
    header_.payload_length = Endian::host_to_be(new_payload_length);
}

void IPv6::next_header(uint8_t new_next_header) {
    next_header_ = header_.next_header = new_next_header;
}

void IPv6::hop_limit(uint8_t new_hop_limit) {
    header_.hop_limit = new_hop_limit;
}

void IPv6::src_addr(const address_type& new_src_addr) {
    new_src_addr.copy(header_.src_addr);
}

void IPv6::dst_addr(const address_type& new_dst_addr) {
    new_dst_addr.copy(header_.dst_addr);
}

uint32_t IPv6::header_size() const {
    return sizeof(header_) + calculate_headers_size();
}

bool IPv6::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(ipv6_header)) {
        return false;
    }
    const ipv6_header* hdr_ptr = (const ipv6_header*)ptr;
    // checks for ff02 multicast
    if (src_addr() == hdr_ptr->dst_addr && 
        (dst_addr() == hdr_ptr->src_addr || (header_.dst_addr[0] == 0xff && header_.dst_addr[1] == 0x02))) {
        // is this OK? there's no inner pdu, simple dst/src addr match should suffice
        if (!inner_pdu()) {
            return true;
        }
        ptr += sizeof(ipv6_header);
        total_sz -= sizeof(ipv6_header);
        uint8_t current = hdr_ptr->next_header;
        // 8 == minimum header size
        while (total_sz > 8 && is_extension_header(current)) {
            if (static_cast<uint32_t>(ptr[1] + 1) * 8 > total_sz) {
                return false;
            }
            current = ptr[0];
            total_sz -= (ptr[1] + 1) * 8;
            ptr += (ptr[1] + 1) * 8;
        }
        if (!is_extension_header(current)) {
            return inner_pdu()->matches_response(ptr, total_sz);
        }
    }
    return false;
}

void IPv6::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);
    vector<uint8_t> header_types;
    // Iterate the headers and store their current values. At the same time, update header X
    // so it has the option type of header X + 1
    for (size_t i = 0; i < ext_headers_.size(); ++i) {
        const uint8_t option = ext_headers_[i].option();
        header_types.push_back(option);
        if (i > 0) {
            ext_headers_[i - 1].option(option);
        }
    }
    // If we have at least one, then update our IPv6 header's next header type
    if (!header_types.empty()) {
        header_.next_header = header_types[0];
    }
    if (inner_pdu()) {
        uint8_t new_flag = Internals::pdu_flag_to_ip_type(inner_pdu()->pdu_type());
        if (new_flag == 0xff && Internals::pdu_type_registered<IPv6>(inner_pdu()->pdu_type())) {
            new_flag = static_cast<Constants::IP::e>(
                Internals::pdu_type_to_id<IPv6>(inner_pdu()->pdu_type())
            );
        }
        // If we managed to find the next flag, then set it. Otherwise, fall back to the 
        // original (or user set) next header
        if (new_flag != 0xff) {
            set_last_next_header(new_flag);
        }
        else {
            set_last_next_header(next_header_);
        }
    }
    else {
        set_last_next_header(0);
    }
    payload_length(static_cast<uint16_t>(total_sz - sizeof(header_)));
    stream.write(header_);
    for (headers_type::const_iterator it = ext_headers_.begin(); it != ext_headers_.end(); ++it) {
        write_header(*it, stream);
    }
    // Restore our original header types
    for (size_t i = 0; i < ext_headers_.size(); ++i) {
        ext_headers_[i].option(header_types[i]);
    }
}

#ifndef BSD
void IPv6::send(PacketSender& sender, const NetworkInterface & interface) {
    sockaddr_in6 link_addr;
    const PacketSender::SocketType type = PacketSender::IPV6_SOCKET;
    link_addr.sin6_family = AF_INET6;
    link_addr.sin6_port = 0;
    if (IPv6Address(header_.dst_addr).is_local_unicast()) {
        link_addr.sin6_scope_id = interface.id();
    }
    memcpy((uint8_t*)&link_addr.sin6_addr, header_.dst_addr, address_type::address_size);
    sender.send_l3(*this, (struct sockaddr*)&link_addr, sizeof(link_addr), type);
}

PDU* IPv6::recv_response(PacketSender& sender, const NetworkInterface &) {
    PacketSender::SocketType type = PacketSender::IPV6_SOCKET;
    if (inner_pdu() && inner_pdu()->pdu_type() == PDU::ICMPv6) {
        type = PacketSender::ICMPV6_SOCKET;
    }
    return sender.recv_l3(*this, 0, sizeof(sockaddr_in6), type);
}
#endif

void IPv6::add_ext_header(const ext_header& header) {
    add_header(header);
}

void IPv6::add_header(const ext_header& header) {
    ext_headers_.push_back(header);
}

const IPv6::ext_header* IPv6::search_header(ExtensionHeader id) const {
    headers_type::const_iterator it = ext_headers_.begin();
    while (it != ext_headers_.end()) {
        if (it->option() == id) {
            return &*it;
        }
        ++it;
    }
    return 0;
}

void IPv6::set_last_next_header(uint8_t value) {
    if (ext_headers_.empty()) {
        header_.next_header = value;
    }
    else {
        ext_headers_.back().option(value);
    }
}

uint32_t IPv6::calculate_headers_size() const {
    typedef headers_type::const_iterator const_iterator;
    uint32_t output = 0;
    for (const_iterator iter = ext_headers_.begin(); iter != ext_headers_.end(); ++iter) {
        output += static_cast<uint32_t>(iter->data_size() + sizeof(uint8_t) * 2);
        output += get_padding_size(*iter);

    }
    return output;
}

void IPv6::write_header(const ext_header& header, OutputMemoryStream& stream) {
    const uint8_t length = header.length_field() / 8;
    stream.write(header.option());
    stream.write(length);
    stream.write(header.data_ptr(), header.data_size());
    // Append padding
    stream.fill(get_padding_size(header), 0);
}

} // Tins
