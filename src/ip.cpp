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
    #include <netdb.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock2.h>
#endif
#include <tins/ip.h>
#include <tins/rawpdu.h>
#include <tins/packet_sender.h>
#include <tins/constants.h>
#include <tins/network_interface.h>
#include <tins/exceptions.h>
#include <tins/pdu_allocator.h>
#include <tins/memory_helpers.h>
#include <tins/utils/checksum_utils.h>
#include <tins/detail/pdu_helpers.h>
#include <tins/pdu_allocator.h>

using std::memcmp;
using std::vector;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

const uint8_t IP::DEFAULT_TTL = 128;

PDU::metadata IP::extract_metadata(const uint8_t *buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(ip_header))) {
        throw malformed_packet();
    }
    const ip_header* header = reinterpret_cast<const ip_header*>(buffer);
    PDUType next_type = Internals::ip_type_to_pdu_flag(
        static_cast<Constants::IP::e>(header->protocol));
    return metadata(header->ihl * 4, pdu_flag, next_type);
}

IP::IP(address_type ip_dst, address_type ip_src) {
    init_ip_fields();
    this->dst_addr(ip_dst);
    this->src_addr(ip_src); 
}

IP::IP(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);

    // Make sure we have enough size for options and not less than we should
    if (TINS_UNLIKELY(head_len() * sizeof(uint32_t) > total_sz || 
                      head_len() * sizeof(uint32_t) < sizeof(header_))) {
        throw malformed_packet();
    }
    const uint8_t* options_end = buffer + head_len() * sizeof(uint32_t);
    
    // While the end of the options is not reached read an option
    while (stream.pointer() < options_end) {
        option_identifier opt_type = option_identifier(stream.read<uint8_t>());
        if (opt_type.number > NOOP) {
            // Multibyte options with length as second byte
            const uint32_t option_size = stream.read<uint8_t>();
            if (TINS_UNLIKELY(option_size < (sizeof(uint8_t) << 1))) {
                throw malformed_packet();
            }
            // The data size is the option size - the identifier and size fields
            const uint32_t data_size = option_size - (sizeof(uint8_t) << 1);
            if (data_size > 0) {
                if (stream.pointer() + data_size > options_end) {
                    throw malformed_packet();
                }
                options_.push_back(
                    option(opt_type, stream.pointer(), stream.pointer() + data_size)
                );
                stream.skip(data_size);
            }
            else {
                options_.push_back(option(opt_type));
            }
        }
        else if (opt_type == END) {
            // If the end option found, we're done
            if (TINS_UNLIKELY(stream.pointer() != options_end)) {
                // Make sure we found the END option at the end of the options list
                throw malformed_packet();
            }
            break;
        }
        else {
            options_.push_back(option(opt_type));
        }
    }
    if (stream) {
        // Don't avoid consuming more than we should if tot_len is 0,
        // since this is the case when using TCP segmentation offload
        if (tot_len() != 0) {
            const uint32_t advertised_length = static_cast<uint32_t>(tot_len()) - head_len() * sizeof(uint32_t);
            const uint32_t stream_size = static_cast<uint32_t>(stream.size());
            total_sz = (stream_size < advertised_length) ? stream_size : advertised_length;
        }
        else {
            total_sz = stream.size();
        }

        // Don't try to decode it if it's fragmented
        if (!is_fragmented()) {
            inner_pdu(
                Internals::pdu_from_flag(
                    static_cast<Constants::IP::e>(header_.protocol),
                    stream.pointer(), 
                    total_sz,
                    false
                )
            );
            if (!inner_pdu()) {
                inner_pdu(
                    Internals::allocate<IP>(
                        header_.protocol,
                        stream.pointer(), 
                        total_sz
                    )
                );
                if (!inner_pdu()) {
                    inner_pdu(new RawPDU(stream.pointer(), total_sz));
                }
            }
        }
        else {
            // It's fragmented, just use RawPDU
            inner_pdu(new RawPDU(stream.pointer(), total_sz));
        }
    }
}

void IP::init_ip_fields() {
    memset(&header_, 0, sizeof(header_));
    header_.version = 4;
    ttl(DEFAULT_TTL);
    id(1);
}

bool IP::is_fragmented() const {
    return (flags() & IP::MORE_FRAGMENTS) != 0 || fragment_offset() != 0;
}

// Setters

void IP::tos(uint8_t new_tos) {
    header_.tos = new_tos;
}

void IP::tot_len(uint16_t new_tot_len) {
    header_.tot_len = Endian::host_to_be(new_tot_len);
}

void IP::id(uint16_t new_id) {
    header_.id = Endian::host_to_be(new_id);
}

void IP::frag_off(uint16_t new_frag_off) {
    header_.frag_off = Endian::host_to_be(new_frag_off);
}

void IP::fragment_offset(small_uint<13> new_frag_off) {
    uint16_t value = (Endian::be_to_host(header_.frag_off) & 0xe000) | new_frag_off;
    header_.frag_off = Endian::host_to_be(value);
}

void IP::flags(Flags new_flags) {
    uint16_t value = (Endian::be_to_host(header_.frag_off) & 0x1fff) | (new_flags << 13);
    header_.frag_off = Endian::host_to_be(value);
}

void IP::ttl(uint8_t new_ttl) {
    header_.ttl = new_ttl;
}

void IP::protocol(uint8_t new_protocol) {
    header_.protocol = new_protocol;
}

void IP::checksum(uint16_t new_check) {
    header_.check = Endian::host_to_be(new_check);
}

void IP::src_addr(address_type ip) {
    header_.saddr = ip;
}

void IP::dst_addr(address_type ip) {
    header_.daddr = ip;
}

void IP::head_len(small_uint<4> new_head_len) {
    header_.ihl = new_head_len;
}

void IP::version(small_uint<4> ver) {
    header_.version = ver;
}

void IP::eol() {
    add_option(option_identifier(IP::END, IP::CONTROL, 0));
}

void IP::noop() {
    add_option(option_identifier(IP::NOOP, IP::CONTROL, 0));
}

void IP::security(const security_type& data) {
    uint8_t array[9];
    OutputMemoryStream stream(array, sizeof(array));
    uint32_t value = data.transmission_control;
    stream.write_be(data.security);
    stream.write_be(data.compartments);
    stream.write_be(data.handling_restrictions);
    stream.write<uint8_t>((value >> 16) & 0xff);
    stream.write<uint8_t>((value >> 8) & 0xff);
    stream.write<uint8_t>(value & 0xff);
    
    add_option(
        option(
            130,
            sizeof(array),
            array
        )
    );
}

void IP::stream_identifier(uint16_t stream_id) {
    stream_id = Endian::host_to_be(stream_id);
    add_option(
        option(
            136,
            sizeof(uint16_t),
            reinterpret_cast<const uint8_t*>(&stream_id)
        )
    );
}

void IP::add_route_option(option_identifier id, const generic_route_option_type& data) {
    vector<uint8_t> opt_data(1 + sizeof(uint32_t) * data.routes.size());
    opt_data[0] = data.pointer;
    for (size_t i(0); i < data.routes.size(); ++i) {
        uint32_t ip = data.routes[i];
        #if TINS_IS_BIG_ENDIAN
            ip = Endian::change_endian(ip);
        #endif
        opt_data[1 + i * 4] = ip & 0xff;
        opt_data[1 + i * 4 + 1] = (ip >> 8) & 0xff;
        opt_data[1 + i * 4 + 2] = (ip >> 16) & 0xff;
        opt_data[1 + i * 4 + 3] = (ip >> 24) & 0xff;
    }
    add_option(
        option(
            id,
            opt_data.size(),
            &opt_data[0]
        )
    );
}

IP::generic_route_option_type IP::search_route_option(option_identifier id) const {
    const option* opt = search_option(id);
    if (!opt) {
        throw option_not_found();
    }
    return opt->to<generic_route_option_type>();
}

IP::security_type IP::security() const {
    const option* opt = search_option(130);
    if (!opt) {
        throw option_not_found();
    }
    return opt->to<security_type>();
}

uint16_t IP::stream_identifier() const {
    const option* opt = search_option(136);
    if (!opt) {
        throw option_not_found();
    }
    return opt->to<uint16_t>();
}

void IP::add_option(const option& opt) {
    options_.push_back(opt);
}

uint32_t IP::calculate_options_size() const {
    uint32_t options_size = 0;
    for (options_type::const_iterator iter = options_.begin(); iter != options_.end(); ++iter) {
        options_size += sizeof(uint8_t);
        const option_identifier option_id = iter->option();
        // Only add length field and data size for non [NOOP, EOL] options
        if (option_id.op_class != CONTROL || option_id.number > NOOP) {
            options_size += sizeof(uint8_t) + iter->data_size();
        }
    }
    return options_size;    
}

uint32_t IP::pad_options_size(uint32_t size) const {
    uint8_t padding = size % 4;
    return padding ? (size - padding + 4) : size;
}

bool IP::remove_option(option_identifier id) {
    options_type::iterator iter = search_option_iterator(id);
    if (iter == options_.end()) {
        return false;
    }
    options_.erase(iter);
    return true;
}

const IP::option* IP::search_option(option_identifier id) const {
    options_type::const_iterator iter = search_option_iterator(id);
    return (iter != options_.end()) ? &*iter : 0;
}

IP::options_type::const_iterator IP::search_option_iterator(option_identifier id) const {
    return Internals::find_option_const<option>(options_, id);
}

IP::options_type::iterator IP::search_option_iterator(option_identifier id) {
    return Internals::find_option<option>(options_, id);
}

void IP::write_option(const option& opt, OutputMemoryStream& stream) {
    stream.write(opt.option());
    // Check what we wrote. We'll do this for any option != [END, NOOP]
    if (*(stream.pointer() - 1) > NOOP) {
        uint8_t length = opt.length_field();
        if (opt.data_size() == opt.length_field()) {
            length += 2;
        }
        stream.write(length);
        stream.write(opt.data_ptr(), opt.data_size());
    }
}

// Virtual method overriding

uint32_t IP::header_size() const {
    return sizeof(header_) + pad_options_size(calculate_options_size());
}

PacketSender::SocketType pdu_type_to_sender_type(PDU::PDUType type) {
    switch(type) {
        case PDU::TCP:
            return PacketSender::IP_TCP_SOCKET;
        case PDU::UDP:
            return PacketSender::IP_UDP_SOCKET;
        case PDU::ICMP:
            return PacketSender::ICMP_SOCKET;
        default:
            return PacketSender::IP_RAW_SOCKET;
    }
}

void IP::send(PacketSender& sender, const NetworkInterface &) {
    sockaddr_in link_addr;
    PacketSender::SocketType type = PacketSender::IP_RAW_SOCKET;
    link_addr.sin_family = AF_INET;
    link_addr.sin_port = 0;
    link_addr.sin_addr.s_addr = header_.daddr;
    if (inner_pdu()) {
        type = pdu_type_to_sender_type(inner_pdu()->pdu_type());
    }

    sender.send_l3(*this, reinterpret_cast<struct sockaddr*>(&link_addr), sizeof(link_addr), type);
}

PDU* IP::recv_response(PacketSender& sender, const NetworkInterface &) {
    sockaddr_in link_addr;
    PacketSender::SocketType type = PacketSender::IP_RAW_SOCKET;
    memset(&link_addr, 0, sizeof(link_addr));
    if (inner_pdu()) {
        type = pdu_type_to_sender_type(inner_pdu()->pdu_type());
    }

    return sender.recv_l3(*this, 0, sizeof(link_addr), type);
}

void IP::prepare_for_serialize() {
    if (!parent_pdu()&& header_.saddr == 0) {
        NetworkInterface iface(dst_addr());
        src_addr(iface.addresses().ip_addr);
    }
}

void IP::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);
    checksum(0);
    if (inner_pdu()) {
        uint32_t new_flag = Internals::pdu_flag_to_ip_type(inner_pdu()->pdu_type());
        if (new_flag == 0xff && Internals::pdu_type_registered<IP>(inner_pdu()->pdu_type())) {
            new_flag = static_cast<Constants::IP::e>(
                Internals::pdu_type_to_id<IP>(inner_pdu()->pdu_type())
            );
        }
        if (new_flag != 0xff) {
            protocol(new_flag);
        }
    }
    else {
        protocol(0);
    }

    uint16_t original_frag_off = header_.frag_off;
    
    #if __FreeBSD__ || defined(__FreeBSD_kernel__) || __APPLE__
        if (!parent_pdu()) {
            total_sz = Endian::host_to_be<uint16_t>(total_sz);
            header_.frag_off = Endian::be_to_host(header_.frag_off);
        }
    #endif
    tot_len(total_sz);
    head_len(static_cast<uint8_t>(header_size() / sizeof(uint32_t)));

    stream.write(header_);

    // Restore the fragment offset field in case we flipped it
    header_.frag_off = original_frag_off;

    for (options_type::const_iterator it = options_.begin(); it != options_.end(); ++it) {
        write_option(*it, stream);
    }
    const uint32_t options_size = calculate_options_size();
    const uint32_t padded_options_size = pad_options_size(options_size);
    // Add option padding
    stream.fill(padded_options_size - options_size, 0);

    uint32_t check = Utils::do_checksum(buffer, stream.pointer());
    while (check >> 16) {
        check = (check & 0xffff) + (check >> 16);
    }
    checksum(~check);
    (reinterpret_cast<ip_header*>(buffer))->check = header_.check;
}

bool IP::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(header_)) {
        return false;
    }
    const ip_header* ip_ptr = reinterpret_cast<const ip_header*>(ptr);
    // dest unreachable?
    if (ip_ptr->protocol == Constants::IP::PROTO_ICMP) {
        const uint8_t* pkt_ptr = ptr + sizeof(ip_header);
        uint32_t pkt_sz = total_sz - sizeof(ip_header);
        // It's an ICMP dest unreachable
        if (pkt_sz > 4 && pkt_ptr[0] == 3) {
            pkt_ptr += 4;
            pkt_sz -= 4;
            // If our IP header is in the ICMP payload, then it's the same packet.
            // This keeps in mind checksum and IP identifier, so I guess it's enough.
            if (pkt_sz >= sizeof(header_) && memcmp(&header_, pkt_ptr, sizeof(ip_header))) {
                return true;
            }
        }
    }
    // checks for broadcast addr
    if ((header_.saddr == ip_ptr->daddr && 
        (header_.daddr == ip_ptr->saddr || dst_addr().is_broadcast())) ||
        (dst_addr().is_broadcast() && header_.saddr == 0)) {

        uint32_t sz = (header_size() < total_sz) ? header_size() : total_sz;
        return inner_pdu() ? inner_pdu()->matches_response(ptr + sz, total_sz - sz) : true;
    }
    return false;
}

// Option static constructors from options

IP::security_type IP::security_type::from_option(const option& opt)  {
    if (opt.data_size() != 9) {
        throw malformed_option();
    }
    security_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.security = stream.read_be<uint16_t>();
    output.compartments = stream.read_be<uint16_t>();
    output.handling_restrictions = stream.read_be<uint16_t>();
    uint32_t tcc = stream.read<uint8_t>();
    tcc = (tcc << 8) | stream.read<uint8_t>();
    tcc = (tcc << 8) | stream.read<uint8_t>();
    output.transmission_control = tcc;
    return output;
}

IP::generic_route_option_type IP::generic_route_option_type::from_option(const option& opt)  {
    if (opt.data_size() < 1 + sizeof(uint32_t) || ((opt.data_size() - 1) % sizeof(uint32_t)) != 0) {
        throw malformed_option();
    }
    generic_route_option_type output;
    output.pointer = *opt.data_ptr();
    const uint8_t* route = opt.data_ptr() + 1;
    const uint8_t* end = route + opt.data_size() - 1;

    uint32_t uint32_t_buffer;
    while (route < end) {
        memcpy(&uint32_t_buffer, route, sizeof(uint32_t));
        output.routes.push_back(address_type(uint32_t_buffer));
        route += sizeof(uint32_t);
    }
    return output;
}

} // namespace Tins
