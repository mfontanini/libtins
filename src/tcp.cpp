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

#include <cstring>
#include <algorithm>
#include "tcp.h"
#include "ip.h"
#include "ipv6.h"
#include "constants.h"
#include "rawpdu.h"
#include "utils.h"
#include "exceptions.h"
#include "internals.h"
#include "memory_helpers.h"

using std::find_if;
using std::min;
using std::vector;
using std::pair;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

const uint16_t TCP::DEFAULT_WINDOW = 32678;

PDU::metadata TCP::extract_metadata(const uint8_t *buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(tcp_header))) {
        throw malformed_packet();
    }
    const tcp_header* header = (const tcp_header*)buffer;
    return metadata(header->doff * 4, pdu_flag, PDU::UNKNOWN);
}

TCP::TCP(uint16_t dport, uint16_t sport) 
: header_(), options_size_(0), total_options_size_(0) {
    this->dport(dport);
    this->sport(sport);
    data_offset(sizeof(tcp_header) / sizeof(uint32_t));
    window(DEFAULT_WINDOW);
}

TCP::TCP(const uint8_t* buffer, uint32_t total_sz) 
: options_size_(0), total_options_size_(0) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    // Check that we have at least the amount of bytes we need and not less
    if (TINS_UNLIKELY(data_offset() * sizeof(uint32_t) > total_sz || 
                      data_offset() * sizeof(uint32_t) < sizeof(tcp_header))) {
        throw malformed_packet();
    }
    const uint8_t* header_end = buffer + (data_offset() * sizeof(uint32_t));

    while (stream.pointer() < header_end) {
        const OptionTypes option_type = (OptionTypes)stream.read<uint8_t>();
        if (option_type <= NOP) {
            #if TINS_IS_CXX11
            add_option(option_type, 0);
            #else
            add_option(option(option_type, 0));
            #endif // TINS_IS_CXX11
        }
        else {
            // Extract the length
            uint32_t len = stream.read<uint8_t>();
            const uint8_t* data_start = stream.pointer();

            // We need to subtract the option type and length from the size
            if (TINS_UNLIKELY(len < sizeof(uint8_t) << 1)) {
                throw malformed_packet();
            }
            len -= (sizeof(uint8_t) << 1);
            // Make sure we have enough bytes for the advertised option payload length
            if (TINS_UNLIKELY(data_start + len > header_end)) {
                throw malformed_packet(); 
            }
            // If we're using C++11, use the variadic template overload
            #if TINS_IS_CXX11
            add_option(option_type, data_start, data_start + len);
            #else
            add_option(option(option_type, data_start, data_start + len));
            #endif // TINS_IS_CXX11
            // Skip the option's payload
            stream.skip(len);
        }
    }
    // If we still have any bytes left
    if (stream) {
        inner_pdu(new RawPDU(stream.pointer(), stream.size()));
    }
}

void TCP::dport(uint16_t new_dport) {
    header_.dport = Endian::host_to_be(new_dport);
}

void TCP::sport(uint16_t new_sport) {
    header_.sport = Endian::host_to_be(new_sport);
}

void TCP::seq(uint32_t new_seq) {
    header_.seq = Endian::host_to_be(new_seq);
}

void TCP::ack_seq(uint32_t new_ack_seq) {
    header_.ack_seq = Endian::host_to_be(new_ack_seq);
}

void TCP::window(uint16_t new_window) {
    header_.window = Endian::host_to_be(new_window);
}

void TCP::checksum(uint16_t new_check) {
    header_.check = Endian::host_to_be(new_check);
}

void TCP::urg_ptr(uint16_t new_urg_ptr) {
    header_.urg_ptr = Endian::host_to_be(new_urg_ptr);
}

void TCP::data_offset(small_uint<4> new_doff) {
    this->header_.doff = new_doff;
}

void TCP::mss(uint16_t value) {
    value = Endian::host_to_be(value);
    add_option(option(MSS, 2, (uint8_t*)&value));
}

uint16_t TCP::mss() const {
    return generic_search<uint16_t>(MSS);
}

void TCP::winscale(uint8_t value) {
    add_option(option(WSCALE, 1, &value));
}

uint8_t TCP::winscale() const {
    return generic_search<uint8_t>(WSCALE);
}

void TCP::sack_permitted() {
    add_option(option(SACK_OK, 0));
}

bool TCP::has_sack_permitted() const {
    return search_option(SACK_OK) != NULL;
}

void TCP::sack(const sack_type& edges) {
    vector<uint8_t> value(edges.size() * sizeof(uint32_t));
    if (edges.size()) {
        OutputMemoryStream stream(value);
        for (sack_type::const_iterator it = edges.begin(); it != edges.end(); ++it) {
            stream.write_be(*it);
        }
    }
    add_option(option(SACK, (uint8_t)value.size(), &value[0]));
}

TCP::sack_type TCP::sack() const {
    const option* opt = search_option(SACK);
    if (!opt) {
        throw option_not_found();
    }
    return opt->to<sack_type>();
}

void TCP::timestamp(uint32_t value, uint32_t reply) {
    uint64_t buffer = (uint64_t(value) << 32) | reply;
    buffer = Endian::host_to_be(buffer);
    add_option(option(TSOPT, 8, (uint8_t*)&buffer));
}

pair<uint32_t, uint32_t> TCP::timestamp() const {
    const option* opt = search_option(TSOPT);
    if (!opt) {
        throw option_not_found();
    }
    return opt->to<pair<uint32_t, uint32_t> >();
}

void TCP::altchecksum(AltChecksums value) {
    uint8_t int_value = value;
    add_option(option(ALTCHK, 1, &int_value));
}

TCP::AltChecksums TCP::altchecksum() const {
    return static_cast<AltChecksums>(generic_search<uint8_t>(ALTCHK));
}

small_uint<1> TCP::get_flag(Flags tcp_flag) const {
    switch (tcp_flag) {
        case FIN:
            return header_.flags.fin;
            break;
        case SYN:
            return header_.flags.syn;
            break;
        case RST:
            return header_.flags.rst;
            break;
        case PSH:
            return header_.flags.psh;
            break;
        case ACK:
            return header_.flags.ack;
            break;
        case URG:
            return header_.flags.urg;
            break;
        case ECE:
            return header_.flags.ece;
            break;
        case CWR:
            return header_.flags.cwr;
            break;
        default:
            return 0;
            break;
    };
}

small_uint<12> TCP::flags() const {
    return (header_.res1 << 8) | header_.flags_8;
}

void TCP::set_flag(Flags tcp_flag, small_uint<1> value) {
    switch (tcp_flag) {
        case FIN:
            header_.flags.fin = value;
            break;
        case SYN:
            header_.flags.syn = value;
            break;
        case RST:
            header_.flags.rst = value;
            break;
        case PSH:
            header_.flags.psh = value;
            break;
        case ACK:
            header_.flags.ack = value;
            break;
        case URG:
            header_.flags.urg = value;
            break;
        case ECE:
            header_.flags.ece = value;
            break;
        case CWR:
            header_.flags.cwr = value;
            break;
    };
}

void TCP::flags(small_uint<12> value) {
    header_.res1 = (value >> 8) & 0x0f;
    header_.flags_8 = value & 0xff;
}

void TCP::add_option(const option& opt) {
    options_.push_back(opt);
    internal_add_option(opt);
}

uint32_t TCP::header_size() const {
    return sizeof(header_) + total_options_size_;
}

void TCP::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent) {
    OutputMemoryStream stream(buffer, total_sz);
    // Set checksum to 0, we'll calculate it at the end
    checksum(0);
    header_.doff = (sizeof(tcp_header) + total_options_size_) / sizeof(uint32_t);
    stream.write(header_);
    for (options_type::const_iterator it = options_.begin(); it != options_.end(); ++it) {
        write_option(*it, stream);
    }

    if (options_size_ < total_options_size_) {
        const uint16_t padding = total_options_size_ - options_size_;
        stream.fill(padding, 1);
    }

    uint32_t check = 0;
    if (const Tins::IP* ip_packet = tins_cast<const Tins::IP*>(parent)) {
        check = Utils::pseudoheader_checksum(
            ip_packet->src_addr(),  
            ip_packet->dst_addr(), 
            size(), 
            Constants::IP::PROTO_TCP
        ) + Utils::sum_range(buffer, buffer + total_sz);
    }
    else if (const Tins::IPv6* ipv6_packet = tins_cast<const Tins::IPv6*>(parent)) {
        check = Utils::pseudoheader_checksum(
            ipv6_packet->src_addr(),  
            ipv6_packet->dst_addr(), 
            size(), 
            Constants::IP::PROTO_TCP
        ) + Utils::sum_range(buffer, buffer + total_sz);
    }
    else {
        return;
    }
    // Convert this 32-bit value into a 16-bit value
    while (check >> 16) {
            check = (check & 0xffff) + (check >> 16);
    }
    checksum(Endian::host_to_be<uint16_t>(~check));
    ((tcp_header*)buffer)->check = header_.check;
}

const TCP::option* TCP::search_option(OptionTypes type) const {
    // Search for the iterator. If we found something, return it, otherwise return nullptr.
    options_type::const_iterator iter = search_option_iterator(type);
    return (iter != options_.end()) ? &*iter : 0;
}

TCP::options_type::const_iterator TCP::search_option_iterator(OptionTypes type) const {
    Internals::option_type_equality_comparator<option> comparator(type);
    return find_if(options_.begin(), options_.end(), comparator);
}

TCP::options_type::iterator TCP::search_option_iterator(OptionTypes type) {
    Internals::option_type_equality_comparator<option> comparator(type);
    return find_if(options_.begin(), options_.end(), comparator);
}

/* options */

void TCP::write_option(const option& opt, OutputMemoryStream& stream) {
    stream.write<uint8_t>(opt.option());
    // Only do this for non EOL nor NOP options 
    if (opt.option() > 1) {
        uint8_t length = opt.length_field();
        // Only add the identifier and size field sizes if the length
        // field hasn't been spoofed.
        if (opt.length_field() == opt.data_size()) {
            length += (sizeof(uint8_t) << 1);
        }
        stream.write(length);
        stream.write(opt.data_ptr(), opt.data_size());
    }
}

void TCP::update_options_size() {
    uint8_t padding = options_size_ & 3;
    total_options_size_ = (padding) ? (options_size_ - padding + 4) : options_size_;
}

void TCP::internal_add_option(const option& opt) {
    options_size_ += sizeof(uint8_t);
    // SACK_OK contains length but not data....
    if (opt.data_size() || opt.option() == SACK_OK) {
        options_size_ += sizeof(uint8_t);    
        options_size_ += static_cast<uint16_t>(opt.data_size());
    }
    update_options_size();
}

bool TCP::remove_option(OptionTypes type) {
    options_type::iterator iter = search_option_iterator(type);
    if (iter == options_.end()) {
        return false;
    }
    options_size_ -= sizeof(uint8_t);
    // SACK_OK contains length but not data....
    if (iter->data_size() || iter->option() == SACK_OK) {
        options_size_ -= sizeof(uint8_t);
        options_size_ -= static_cast<uint16_t>(iter->data_size());
    }
    options_.erase(iter);
    update_options_size();
    return true;
}

bool TCP::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(header_)) {
        return false;
    }
    const tcp_header* tcp_ptr = (const tcp_header*)ptr;
    if (tcp_ptr->sport == header_.dport && tcp_ptr->dport == header_.sport) {
        uint32_t sz = min<uint32_t>(total_sz, tcp_ptr->doff * sizeof(uint32_t));
        return inner_pdu() ? inner_pdu()->matches_response(ptr + sz, total_sz - sz) : true;
    }
    else
        return false;
}

} // Tins
