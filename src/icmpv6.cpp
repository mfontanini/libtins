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
#include "icmpv6.h"
#include "ipv6.h"
#include "rawpdu.h"
#include "utils.h"
#include "constants.h"
#include "exceptions.h"
#include "memory_helpers.h"

using std::memset;
using std::vector;
using std::string;
using std::max;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

ICMPv6::ICMPv6(Types tp)
: options_size_(), reach_time_(0), retrans_timer_(0), mlqm_(), use_mldv2_(true) {
    memset(&header_, 0, sizeof(header_));
    type(tp);
}

ICMPv6::ICMPv6(const uint8_t* buffer, uint32_t total_sz) 
: options_size_(), reach_time_(0), retrans_timer_(0), mlqm_(), use_mldv2_(true) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    if (has_target_addr()) {
        target_address_ = stream.read<ipaddress_type>();
    }
    if (has_dest_addr()) {
        dest_address_ = stream.read<ipaddress_type>();
    }
    if (type() == ROUTER_ADVERT) {
        reach_time_ = stream.read<uint32_t>();
        retrans_timer_ = stream.read<uint32_t>();
    }
    else if (type() == MLD2_REPORT) {
        uint16_t record_count = Endian::be_to_host(header_.mlrm2.record_count);
        for (uint16_t i = 0; i < record_count; ++i) {
            multicast_records_.push_back(
                multicast_address_record(stream.pointer(), stream.size())
            );
            stream.skip(multicast_records_.back().size());
        }
    }
    else if (type() == MGM_QUERY) {
        stream.read(multicast_address_);
        // MLDv1 ends here
        use_mldv2_ = stream;
        if (stream) {
            stream.read(mlqm_);
            int sources_count = stream.read_be<uint16_t>();
            while (sources_count--) {
                ipaddress_type address;
                stream.read(address);
                sources_.push_back(address);
            }
        }
    }
    // Retrieve options
    if (has_options()) {
        parse_options(stream);
    }
    // Attempt to parse ICMP extensions
    try_parse_extensions(stream);
    if (stream) {
        inner_pdu(new RawPDU(stream.pointer(), stream.size()));
    }
}

void ICMPv6::parse_options(InputMemoryStream& stream) {
    while (stream) {
        const uint8_t opt_type = stream.read<uint8_t>();
        const uint32_t opt_size = static_cast<uint32_t>(stream.read<uint8_t>()) * 8;
        if (opt_size < sizeof(uint8_t) << 1) {
            throw malformed_packet();
        }
        // size(option) = option_size - identifier_size - length_identifier_size
        const uint32_t payload_size = opt_size - (sizeof(uint8_t) << 1);
        if (!stream.can_read(payload_size)) { 
            throw malformed_packet();
        }
        add_option(
            option(
                opt_type, 
                payload_size, 
                stream.pointer()
            )
        );
        stream.skip(payload_size);
    }
}

void ICMPv6::type(Types new_type) {
    header_.type = new_type;
}

void ICMPv6::code(uint8_t new_code) {
    header_.code = new_code;
}

void ICMPv6::checksum(uint16_t new_cksum) {
    header_.cksum = Endian::host_to_be(new_cksum);
}

void ICMPv6::identifier(uint16_t new_identifier) {
    header_.u_echo.identifier = Endian::host_to_be(new_identifier);
}

void ICMPv6::sequence(uint16_t new_sequence) {
    header_.u_echo.sequence = Endian::host_to_be(new_sequence);
}

void ICMPv6::override(small_uint<1> new_override) {
    header_.u_nd_advt.override = new_override;
}

void ICMPv6::solicited(small_uint<1> new_solicited) {
    header_.u_nd_advt.solicited = new_solicited;
}

void ICMPv6::router(small_uint<1> new_router) {
    header_.u_nd_advt.router = new_router;
}

void ICMPv6::hop_limit(uint8_t new_hop_limit) {
    header_.u_nd_ra.hop_limit = new_hop_limit;
}

void ICMPv6::maximum_response_code(uint16_t maximum_response_code) {
    header_.u_echo.identifier = Endian::host_to_be(maximum_response_code);
}

void ICMPv6::router_pref(small_uint<2> new_router_pref) {
    header_.u_nd_ra.router_pref = new_router_pref;
}

void ICMPv6::home_agent(small_uint<1> new_home_agent) {
    header_.u_nd_ra.home_agent = new_home_agent;
}

void ICMPv6::other(small_uint<1> new_other) {
    header_.u_nd_ra.other = new_other;
}

void ICMPv6::managed(small_uint<1> new_managed) {
    header_.u_nd_ra.managed = new_managed;
}

void ICMPv6::router_lifetime(uint16_t new_router_lifetime) {
    header_.u_nd_ra.router_lifetime = Endian::host_to_be(new_router_lifetime);
}

void ICMPv6::reachable_time(uint32_t new_reachable_time) {
    reach_time_ = Endian::host_to_be(new_reachable_time);
}

void ICMPv6::retransmit_timer(uint32_t new_retrans_timer_) {
    retrans_timer_ = Endian::host_to_be(new_retrans_timer_);
}

void ICMPv6::multicast_address_records(const multicast_address_records_list& records) {
    multicast_records_ = records;
}

void ICMPv6::sources(const sources_list& new_sources) {
    sources_ = new_sources;
}

void ICMPv6::supress(small_uint<1> value) {
    mlqm_.supress = value;
}

void ICMPv6::qrv(small_uint<3> value) {
    mlqm_.qrv = value;
}

void ICMPv6::qqic(uint8_t value) {
    mlqm_.qqic = value;
}

void ICMPv6::target_addr(const ipaddress_type& new_target_addr) {
    target_address_ = new_target_addr;
}

void ICMPv6::dest_addr(const ipaddress_type& new_dest_addr) {
    dest_address_ = new_dest_addr;
}

void ICMPv6::multicast_addr(const ipaddress_type& new_multicast_addr) {
    multicast_address_ = new_multicast_addr;
}

uint32_t ICMPv6::header_size() const {
    uint32_t extra = 0;
    if (type() == ROUTER_ADVERT) {
        extra = sizeof(uint32_t) * 2;
    }
    else if (type() == MLD2_REPORT) {
        typedef multicast_address_records_list::const_iterator iterator;
        for (iterator iter = multicast_records_.begin(); 
             iter != multicast_records_.end(); ++iter) {
            extra += iter->size();
        }
    }
    else if (type() == MGM_QUERY) {
        extra += ipaddress_type::address_size;
        if (use_mldv2_) {
            extra += sizeof(mlqm_) + sizeof(uint16_t) + 
                     ipaddress_type::address_size * sources_.size();
        }
    }
    return sizeof(header_) + options_size_ + extra + 
        (has_target_addr() ? ipaddress_type::address_size : 0) +
        (has_dest_addr() ? ipaddress_type::address_size : 0);
}

uint32_t ICMPv6::trailer_size() const {
    uint32_t output = 0;
    if (has_extensions()) {
        output += extensions_.size();
        if (inner_pdu()) {
            // This gets how much padding we'll use. 
            // If the next pdu size is lower than 128 bytes, then padding = 128 - pdu size
            // If the next pdu size is greater than 128 bytes, 
            // then padding = pdu size padded to next 32 bit boundary - pdu size
            const uint32_t upper_bound = max(get_adjusted_inner_pdu_size(), 128U);
            output += upper_bound - inner_pdu()->size();
        }
    }
    return output;
}

void ICMPv6::use_length_field(bool value) {
    // We just need a non 0 value here, we'll use the right value on 
    // write_serialization
    header_.rfc4884.length = value ? 1 : 0;
}

bool ICMPv6::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(header_)) {
        return false;
    }
    const icmp6_header* hdr_ptr = (const icmp6_header*)ptr;
    if (type() == ECHO_REQUEST && hdr_ptr->type == ECHO_REPLY) {
        return hdr_ptr->u_echo.identifier == header_.u_echo.identifier &&
               hdr_ptr->u_echo.sequence == header_.u_echo.sequence;
    }
    return false;
}

void ICMPv6::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent) {
    OutputMemoryStream stream(buffer, total_sz);

    // If extensions are allowed and we have to set the length field
    if (are_extensions_allowed()) {
        uint32_t length_value = get_adjusted_inner_pdu_size();
        // If the next pdu size is greater than 128, we are forced to set the length field
        if (length() != 0 || length_value > 128) {
            length_value = length_value ? max(length_value, 128U) : 0;
            // This field uses 64 bit words as the unit
            header_.rfc4884.length = length_value / sizeof(uint64_t);
        }
    }
    // Initially set checksum to 0, we'll calculate it at the end
    header_.cksum = 0;
    // Update the MLRM record count before writing the header
    if (type() == MLD2_REPORT) {
        header_.mlrm2.record_count = Endian::host_to_be<uint16_t>(multicast_records_.size());
    }
    stream.write(header_);

    if (has_target_addr()) {
        stream.write(target_address_);
    }
    if (has_dest_addr()) {
        stream.write(dest_address_);
    }
    if (type() == ROUTER_ADVERT) {
        stream.write(reach_time_);
        stream.write(retrans_timer_);
    }
    else if (type() == MLD2_REPORT) {
        typedef multicast_address_records_list::const_iterator iterator;
        for (iterator iter = multicast_records_.begin(); 
             iter != multicast_records_.end(); ++iter) {
            iter->serialize(stream.pointer(), stream.size());
            stream.skip(iter->size());
        }
    }
    else if (type() == MGM_QUERY) {
        stream.write(multicast_address_);
        // Only write this if we're using MLDv2
        if (use_mldv2_) {
            stream.write(mlqm_);
            stream.write_be<uint16_t>(sources_.size());
            typedef sources_list::const_iterator iterator;
            for (iterator iter = sources_.begin(); iter != sources_.end(); ++iter) {
                stream.write(*iter);
            } 
        }
    }
    for (options_type::const_iterator it = options_.begin(); it != options_.end(); ++it) {
        write_option(*it, stream);
    }

    if (has_extensions()) {
        uint8_t* extensions_ptr = stream.pointer();
        if (inner_pdu()) {
            // Get the size of the next pdu, padded to the next 32 bit boundary
            uint32_t inner_pdu_size = get_adjusted_inner_pdu_size();
            // If it's lower than 128, we need to padd enough zeroes to make it 128 bytes long
            if (inner_pdu_size < 128) {
                memset(extensions_ptr + inner_pdu_size, 0, 128 - inner_pdu_size);
                inner_pdu_size = 128;
            }
            else {
                // If the packet has to be padded to 64 bits, append the amount 
                // of zeroes we need
                uint32_t diff = inner_pdu_size - inner_pdu()->size();
                memset(extensions_ptr + inner_pdu_size, 0, diff);
            }
            extensions_ptr += inner_pdu_size;
        }
        // Now serialize the exensions where they should be
        extensions_.serialize(
            extensions_ptr, 
            total_sz - (extensions_ptr - stream.pointer())
        );
    }

    const Tins::IPv6* ipv6 = tins_cast<const Tins::IPv6*>(parent);
    if (ipv6) {
        uint32_t checksum = Utils::pseudoheader_checksum(
            ipv6->src_addr(),  
            ipv6->dst_addr(), 
            size(), 
            Constants::IP::PROTO_ICMPV6
        ) + Utils::sum_range(buffer, buffer + total_sz);
        while (checksum >> 16) {
            checksum = (checksum & 0xffff) + (checksum >> 16);
        }
        header_.cksum = ~checksum & 0xffff;
        memcpy(buffer + 2, &header_.cksum, sizeof(uint16_t));
    }
}

uint8_t ICMPv6::get_option_padding(uint32_t data_size) {
    uint8_t padding = 8 - data_size % 8;
    if (padding == 8) {
        padding = 0;
    }
    return padding;
}

// can i haz more?
bool ICMPv6::has_options() const {
    switch (type()) {
        case NEIGHBOUR_SOLICIT:
        case NEIGHBOUR_ADVERT:
        case ROUTER_SOLICIT:
        case ROUTER_ADVERT:
        case REDIRECT:
            return true;
        default:
            return false;
    }
}

void ICMPv6::add_option(const option& option) {
    internal_add_option(option);
    options_.push_back(option);
}

void ICMPv6::internal_add_option(const option& option) {
    options_size_ += static_cast<uint32_t>(option.data_size() + sizeof(uint8_t) * 2);
}

bool ICMPv6::remove_option(OptionTypes type) {
    options_type::iterator iter = search_option_iterator(type);
    if (iter == options_.end()) {
        return false;
    }
    options_size_ -= static_cast<uint32_t>(iter->data_size() + sizeof(uint8_t) * 2);
    options_.erase(iter);
    return true;
}

void ICMPv6::write_option(const option& opt, OutputMemoryStream& stream) {
    stream.write(opt.option());
    stream.write<uint8_t>((opt.length_field() + sizeof(uint8_t) * 2) / 8);
    stream.write(opt.data_ptr(), opt.data_size());
}

void ICMPv6::use_mldv2(bool value) {
    use_mldv2_ = value;
}

const ICMPv6::option* ICMPv6::search_option(OptionTypes type) const {
    // Search for the iterator. If we found something, return it, otherwise return nullptr.
    options_type::const_iterator iter = search_option_iterator(type);
    return (iter != options_.end()) ? &*iter : 0;
}

ICMPv6::options_type::const_iterator ICMPv6::search_option_iterator(OptionTypes type) const {
    Internals::option_type_equality_comparator<option> comparator(type);
    return find_if(options_.begin(), options_.end(), comparator);
}

ICMPv6::options_type::iterator ICMPv6::search_option_iterator(OptionTypes type) {
    Internals::option_type_equality_comparator<option> comparator(type);
    return find_if(options_.begin(), options_.end(), comparator);
}

// ********************************************************************
//                          Option setters
// ********************************************************************

void ICMPv6::source_link_layer_addr(const hwaddress_type& addr) {
    add_option(option(SOURCE_ADDRESS, addr.begin(), addr.end()));
}

void ICMPv6::target_link_layer_addr(const hwaddress_type& addr) {
    add_option(option(TARGET_ADDRESS, addr.begin(), addr.end()));
}

void ICMPv6::prefix_info(prefix_info_type info) {
    uint8_t buffer[2 + sizeof(uint32_t) * 3 + ipaddress_type::address_size];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write(info.prefix_len);
    stream.write<uint8_t>((info.L << 7) | (info.A << 6));
    stream.write_be(info.valid_lifetime);
    stream.write_be(info.preferred_lifetime);
    stream.write<uint32_t>(0);
    stream.write(info.prefix);
    add_option(
        option(PREFIX_INFO, buffer, buffer + sizeof(buffer))
    );
}

void ICMPv6::redirect_header(const byte_array& data) {
    add_option(option(REDIRECT_HEADER, data.begin(), data.end()));
}

void ICMPv6::mtu(const mtu_type& value) {
    uint8_t buffer[sizeof(uint16_t) + sizeof(uint32_t)];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write_be(value.first);
    stream.write_be(value.second);
    add_option(option(MTU, sizeof(buffer), buffer));
}

void ICMPv6::shortcut_limit(const shortcut_limit_type& value) {
    uint8_t buffer[sizeof(uint16_t) + sizeof(uint32_t)];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write(value.limit);
    stream.write(value.reserved1);
    stream.write_be(value.reserved2);
    add_option(option(NBMA_SHORT_LIMIT, sizeof(buffer), buffer));
}

void ICMPv6::new_advert_interval(const new_advert_interval_type& value) {
    uint8_t buffer[sizeof(uint16_t) + sizeof(uint32_t)];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write_be(value.reserved);
    stream.write_be(value.interval);
    add_option(option(ADVERT_INTERVAL, sizeof(buffer), buffer));
}

void ICMPv6::new_home_agent_info(const new_ha_info_type& value) {
    if (value.size() != 3) {
        throw malformed_option();
    }
    uint8_t buffer[sizeof(uint16_t) * 3];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write_be(value[0]);
    stream.write_be(value[1]);
    stream.write_be(value[2]);
    add_option(option(HOME_AGENT_INFO, sizeof(buffer), buffer));
}

void ICMPv6::source_addr_list(const addr_list_type& value) {
    add_addr_list(S_ADDRESS_LIST, value);
}

void ICMPv6::target_addr_list(const addr_list_type& value) {
    add_addr_list(T_ADDRESS_LIST, value);
}

void ICMPv6::add_addr_list(uint8_t type, const addr_list_type& value) {
    vector<uint8_t> buffer(value.addresses.size() * ipaddress_type::address_size + 6);
    OutputMemoryStream stream(buffer);
    stream.write(value.reserved, value.reserved + 6);
    for (size_t i = 0; i < value.addresses.size(); ++i) {
        stream.write(value.addresses[i]);
    }
    add_option(option(type, buffer.begin(), buffer.end()));
}

void ICMPv6::rsa_signature(const rsa_sign_type& value) {
    uint32_t total_sz = static_cast<uint32_t>(2 + sizeof(value.key_hash) + value.signature.size());
    uint8_t padding = 8 - total_sz % 8;
    if (padding == 8) {
        padding = 0;
    }
    vector<uint8_t> buffer(total_sz + padding);
    OutputMemoryStream stream(buffer);
    stream.write<uint16_t>(0);
    stream.write(value.key_hash, value.key_hash + sizeof(value.key_hash));
    stream.write(value.signature.begin(), value.signature.end());
    stream.fill(padding, 0);
    add_option(option(RSA_SIGN, buffer.begin(), buffer.end()));
}

void ICMPv6::timestamp(const timestamp_type& value) {
    vector<uint8_t> buffer(6 + sizeof(uint64_t));
    OutputMemoryStream stream(buffer);
    stream.write(value.reserved, value.reserved + 6);
    stream.write_be(value.timestamp);
    add_option(option(TIMESTAMP, buffer.begin(), buffer.end()));
}

void ICMPv6::nonce(const nonce_type& value) {
    add_option(option(NONCE, value.begin(), value.end()));
}

void ICMPv6::ip_prefix(const ip_prefix_type& value) {
    vector<uint8_t> buffer(6 + ipaddress_type::address_size);
    OutputMemoryStream stream(buffer);
    stream.write(value.option_code);
    stream.write(value.prefix_len);
    // reserved
    stream.write<uint32_t>(0);
    stream.write(value.address);
    add_option(option(IP_PREFIX, buffer.begin(), buffer.end()));
}

void ICMPv6::link_layer_addr(lladdr_type value) {
    value.address.insert(value.address.begin(), value.option_code);
    uint8_t padding = get_option_padding(2 + value.address.size());
    value.address.insert(value.address.end(), padding, 0);
    add_option(option(LINK_ADDRESS, value.address.begin(), value.address.end()));
}

void ICMPv6::naack(const naack_type& value) {
    uint8_t buffer[6];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write(value.code);
    stream.write(value.status);
    stream.write(value.reserved, value.reserved + 4);
    add_option(option(NAACK, buffer, buffer + sizeof(buffer)));
}

void ICMPv6::map(const map_type& value) {
    uint8_t buffer[sizeof(uint8_t) * 2 + sizeof(uint32_t) + ipaddress_type::address_size];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write<uint8_t>(value.dist << 4 | value.pref);
    stream.write<uint8_t>(value.r << 7);
    stream.write_be(value.valid_lifetime);
    stream.write(value.address);
    add_option(option(MAP, buffer, buffer + sizeof(buffer)));
}

void ICMPv6::route_info(const route_info_type& value) {
    uint8_t padding = get_option_padding(value.prefix.size());
    vector<uint8_t> buffer(2 + sizeof(uint32_t) + value.prefix.size() + padding);
    OutputMemoryStream stream(buffer);
    stream.write(value.prefix_len);
    stream.write<uint8_t>(value.pref << 3);
    stream.write_be(value.route_lifetime);
    // copy the prefix and then fill with padding
    stream.write(value.prefix.begin(), value.prefix.end());
    stream.fill(padding, 0);
    add_option(option(ROUTE_INFO, buffer.begin(), buffer.end()));
}

void ICMPv6::recursive_dns_servers(const recursive_dns_type& value) {
    vector<uint8_t> buffer(
        2 + sizeof(uint32_t) + value.servers.size() * ipaddress_type::address_size
    );
    OutputMemoryStream stream(buffer);
    stream.write<uint8_t>(0);
    stream.write<uint8_t>(0);
    stream.write_be(value.lifetime);
    
    typedef recursive_dns_type::servers_type::const_iterator iterator;
    for (iterator it = value.servers.begin(); it != value.servers.end(); ++it) {
        stream.write(*it);
    }
    add_option(option(RECURSIVE_DNS_SERV, buffer.begin(), buffer.end()));
}

void ICMPv6::handover_key_request(const handover_key_req_type& value) {
    uint8_t padding = get_option_padding(value.key.size() + 4);
    vector<uint8_t> buffer(2 + value.key.size() + padding);
    OutputMemoryStream stream(buffer);
    stream.write(padding);
    stream.write<uint8_t>(value.AT << 4);
    // copy the key, and fill with padding
    stream.write(value.key.begin(), value.key.end());
    stream.fill(padding, 0);
    add_option(option(HANDOVER_KEY_REQ, buffer.begin(), buffer.end()));
}

void ICMPv6::handover_key_reply(const handover_key_reply_type& value) {
    const uint32_t data_size = static_cast<uint32_t>(value.key.size() + 2 + sizeof(uint16_t));
    uint8_t padding = get_option_padding(data_size+2);
    vector<uint8_t> buffer(data_size + padding);
    OutputMemoryStream stream(buffer);
    stream.write(padding);
    stream.write<uint8_t>(value.AT << 4);
    stream.write_be(value.lifetime);
    // copy the key, and fill with padding
    stream.write(value.key.begin(), value.key.end());
    stream.fill(padding, 0);
    add_option(option(HANDOVER_KEY_REPLY, buffer.begin(), buffer.end()));
}

void ICMPv6::handover_assist_info(const handover_assist_info_type& value) {
    const uint32_t data_size = static_cast<uint32_t>(value.hai.size() + 2);
    uint8_t padding = get_option_padding(data_size+2);
    vector<uint8_t> buffer(data_size + padding);
    OutputMemoryStream stream(buffer);
    stream.write(value.option_code);
    stream.write<uint8_t>(value.hai.size());
    // copy hai + padding
    stream.write(value.hai.begin(), value.hai.end());
    stream.fill(padding, 0);
    add_option(option(HANDOVER_ASSIST_INFO, buffer.begin(), buffer.end()));
}

void ICMPv6::mobile_node_identifier(const mobile_node_id_type& value) {
    const uint32_t data_size = static_cast<uint32_t>(value.mn.size() + 2);
    uint8_t padding = get_option_padding(data_size+2);
    vector<uint8_t> buffer(data_size + padding);
    OutputMemoryStream stream(buffer);
    stream.write(value.option_code);
    stream.write<uint8_t>(value.mn.size());
    // copy mn + padding
    stream.write(value.mn.begin(), value.mn.end());
    stream.fill(padding, 0);
    add_option(option(MOBILE_NODE_ID, buffer.begin(), buffer.end()));
}

void ICMPv6::dns_search_list(const dns_search_list_type& value) {
    // at least it's got this size
    vector<uint8_t> buffer(2 + sizeof(uint32_t));
    OutputMemoryStream stream(buffer);
    stream.skip(2);
    stream.write_be(value.lifetime);
    typedef dns_search_list_type::domains_type::const_iterator iterator;
    for (iterator it = value.domains.begin(); it != value.domains.end(); ++it) {
        size_t prev = 0, index;
        do {
            index = it->find('.', prev);
            string::const_iterator end = (index == string::npos) ? 
                                         it->end() : (it->begin() + index);
            buffer.push_back(static_cast<uint8_t>(end - (it->begin() + prev)));
            buffer.insert(buffer.end(), it->begin() + prev, end);
            prev = index + 1;
        } while (index != string::npos);
        // delimiter
        buffer.push_back(0);
    }
    uint8_t padding = get_option_padding(buffer.size() + 2);
    buffer.insert(buffer.end(), padding, 0);
    add_option(option(DNS_SEARCH_LIST, buffer.begin(), buffer.end()));
}

uint32_t ICMPv6::get_adjusted_inner_pdu_size() const {
    // This gets the size of the next pdu, padded to the next 64 bit word boundary
    return Internals::get_padded_icmp_inner_pdu_size(inner_pdu(), sizeof(uint64_t));
}

void ICMPv6::try_parse_extensions(InputMemoryStream& stream) {
    // Check if this is one of the types defined in RFC 4884
    if (are_extensions_allowed()) {
        Internals::try_parse_icmp_extensions(stream, length() * sizeof(uint64_t), 
            extensions_);
    }
}

bool ICMPv6::are_extensions_allowed() const {
    return type() == TIME_EXCEEDED;
}

// ********************************************************************
//                          Option getters
// ********************************************************************

ICMPv6::hwaddress_type ICMPv6::source_link_layer_addr() const {
    return search_and_convert<hwaddress_type>(SOURCE_ADDRESS);
}

ICMPv6::hwaddress_type ICMPv6::target_link_layer_addr() const {
    return search_and_convert<hwaddress_type>(TARGET_ADDRESS);
}

ICMPv6::prefix_info_type ICMPv6::prefix_info() const {
    return search_and_convert<prefix_info_type>(PREFIX_INFO);
}

byte_array ICMPv6::redirect_header() const {
    return search_and_convert<PDU::serialization_type>(REDIRECT_HEADER);
}

ICMPv6::mtu_type ICMPv6::mtu() const {
    return search_and_convert<mtu_type>(MTU);
}

ICMPv6::shortcut_limit_type ICMPv6::shortcut_limit() const {
    return search_and_convert<shortcut_limit_type>(NBMA_SHORT_LIMIT);
}

ICMPv6::new_advert_interval_type ICMPv6::new_advert_interval() const {
    return search_and_convert<new_advert_interval_type>(ADVERT_INTERVAL);
}

ICMPv6::new_ha_info_type ICMPv6::new_home_agent_info() const {
    return search_and_convert<new_ha_info_type>(HOME_AGENT_INFO);
}

ICMPv6::addr_list_type ICMPv6::source_addr_list() const {
    return search_addr_list(S_ADDRESS_LIST);
}

ICMPv6::addr_list_type ICMPv6::target_addr_list() const {
    return search_addr_list(T_ADDRESS_LIST);
}

ICMPv6::addr_list_type ICMPv6::search_addr_list(OptionTypes type) const {
    return search_and_convert<addr_list_type>(type);
}

ICMPv6::rsa_sign_type ICMPv6::rsa_signature() const {
    return search_and_convert<rsa_sign_type>(RSA_SIGN);
}

ICMPv6::timestamp_type ICMPv6::timestamp() const {
    return search_and_convert<timestamp_type>(TIMESTAMP);
}

ICMPv6::nonce_type ICMPv6::nonce() const {
    return search_and_convert<nonce_type>(NONCE);
}

ICMPv6::ip_prefix_type ICMPv6::ip_prefix() const {
    return search_and_convert<ip_prefix_type>(IP_PREFIX);
}   

ICMPv6::lladdr_type ICMPv6::link_layer_addr() const {
    return search_and_convert<lladdr_type>(LINK_ADDRESS);
}

ICMPv6::naack_type ICMPv6::naack() const {
    return search_and_convert<naack_type>(NAACK);
}

ICMPv6::map_type ICMPv6::map() const {
    return search_and_convert<map_type>(MAP);
}

ICMPv6::route_info_type ICMPv6::route_info() const {
    return search_and_convert<route_info_type>(ROUTE_INFO);
}

ICMPv6::recursive_dns_type ICMPv6::recursive_dns_servers() const {
    return search_and_convert<recursive_dns_type>(RECURSIVE_DNS_SERV);
}

ICMPv6::handover_key_req_type ICMPv6::handover_key_request() const {
    return search_and_convert<handover_key_req_type>(HANDOVER_KEY_REQ);
}

ICMPv6::handover_key_reply_type ICMPv6::handover_key_reply() const {
    return search_and_convert<handover_key_reply_type>(HANDOVER_KEY_REPLY);
}

ICMPv6::handover_assist_info_type ICMPv6::handover_assist_info() const {
    return search_and_convert<handover_assist_info_type>(HANDOVER_ASSIST_INFO);
}

ICMPv6::mobile_node_id_type ICMPv6::mobile_node_identifier() const {
    return search_and_convert<mobile_node_id_type>(MOBILE_NODE_ID);
}

ICMPv6::dns_search_list_type ICMPv6::dns_search_list() const {
    return search_and_convert<dns_search_list_type>(DNS_SEARCH_LIST);
}

// Options stuff

ICMPv6::addr_list_type ICMPv6::addr_list_type::from_option(const option& opt) {
    if (opt.data_size() < 6 + ipaddress_type::address_size || 
        (opt.data_size() - 6) % ipaddress_type::address_size != 0) {
        throw malformed_option();
    }
    addr_list_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    stream.read(output.reserved, 6);
    while (stream) {
        output.addresses.push_back(stream.read<ICMPv6::ipaddress_type>());
    }
    return output;
}

ICMPv6::naack_type ICMPv6::naack_type::from_option(const option& opt) {
    if (opt.data_size() != 6) {
        throw malformed_option();
    }
    return naack_type(*opt.data_ptr(), opt.data_ptr()[1]);
}

ICMPv6::lladdr_type ICMPv6::lladdr_type::from_option(const option& opt) {
    if (opt.data_size() < 2) {
        throw malformed_option();
    }
    const uint8_t* ptr = opt.data_ptr();
    lladdr_type output(*ptr++);
    output.address.assign(ptr, opt.data_ptr() + opt.data_size());
    return output;
}

ICMPv6::prefix_info_type ICMPv6::prefix_info_type::from_option(const option& opt) {
    if (opt.data_size() != 2 + sizeof(uint32_t) * 3 + ICMPv6::ipaddress_type::address_size) {
        throw malformed_option();
    }
    prefix_info_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.prefix_len = stream.read<uint8_t>();
    output.L = (*stream.pointer() >> 7) & 0x1;
    output.A = (stream.read<uint8_t>() >> 6) & 0x1;
    output.valid_lifetime = stream.read_be<uint32_t>();
    output.preferred_lifetime = stream.read_be<uint32_t>();
    output.reserved2 = stream.read_be<uint32_t>();
    output.prefix = stream.read<ICMPv6::ipaddress_type>();
    return output;
}

ICMPv6::rsa_sign_type ICMPv6::rsa_sign_type::from_option(const option& opt) {
    // 2 bytes reserved + at least 1 byte signature.
    // 16 == sizeof(rsa_sign_type::key_hash), removed the sizeof
    // expression since gcc 4.2 doesn't like it
    if (opt.data_size() < 2 + 16 + 1) {
        throw malformed_option();
    }
    rsa_sign_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    stream.skip(2);
    stream.read(output.key_hash, sizeof(output.key_hash));
    output.signature.assign(stream.pointer(), stream.pointer() + stream.size());
    return output;
}

ICMPv6::ip_prefix_type ICMPv6::ip_prefix_type::from_option(const option& opt) {
    // 2 bytes + 4 padding + ipv6 address
    if (opt.data_size() != 2 + 4 + ICMPv6::ipaddress_type::address_size) {
        throw malformed_option();
    }
    ip_prefix_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.option_code = stream.read<uint8_t>();
    output.prefix_len = stream.read<uint8_t>();
    // skip padding
    stream.skip(sizeof(uint32_t));
    stream.read(output.address);
    return output;
}

ICMPv6::map_type ICMPv6::map_type::from_option(const option& opt) {
    if (opt.data_size() != 2 + sizeof(uint32_t) + ipaddress_type::address_size) {
        throw malformed_option();
    }
    map_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.dist = (*stream.pointer() >> 4) & 0x0f;
    output.pref = stream.read<uint8_t>() & 0x0f;
    output.r = (stream.read<uint8_t>() >> 7) & 0x01;
    output.valid_lifetime = stream.read_be<uint32_t>();
    stream.read(output.address);
    return output;
}

ICMPv6::route_info_type ICMPv6::route_info_type::from_option(const option& opt)  {
    if (opt.data_size() < 2 + sizeof(uint32_t)) {
        throw malformed_option();
    }
    route_info_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.prefix_len = stream.read<uint8_t>();
    output.pref = (stream.read<uint8_t>() >> 3) & 0x3;
    output.route_lifetime = stream.read_be<uint32_t>();
    output.prefix.assign(stream.pointer(), stream.pointer() + stream.size());
    return output;
}

ICMPv6::recursive_dns_type ICMPv6::recursive_dns_type::from_option(const option& opt) {
    if (opt.data_size() < 2 + sizeof(uint32_t) + ICMPv6::ipaddress_type::address_size) {
        throw malformed_option();
    }
    recursive_dns_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    stream.skip(2);
    output.lifetime = stream.read_be<uint32_t>();
    while (stream) {
        output.servers.push_back(stream.read<ICMPv6::ipaddress_type>());
    }
    return output;
}

ICMPv6::handover_key_req_type ICMPv6::handover_key_req_type::from_option(const option& opt) {
    if (opt.data_size() < 2 + sizeof(uint32_t)) {
        throw option_not_found();
    }
    handover_key_req_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    stream.skip(1);
    output.AT = (stream.read<uint8_t>() >> 4) & 0x3;
    // is there enough size for the indicated padding?
    if (!stream.can_read(*opt.data_ptr())) {
        throw malformed_option();
    }
    output.key.assign(stream.pointer(), stream.pointer() + stream.size() - *opt.data_ptr());
    return output;
}

ICMPv6::handover_key_reply_type ICMPv6::handover_key_reply_type::from_option(const option& opt) {
    if (opt.data_size() < 2 + sizeof(uint32_t)) {
        throw malformed_option();
    }
    handover_key_reply_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    stream.skip(1);
    output.AT = (stream.read<uint8_t>() >> 4) & 0x3;
    output.lifetime = stream.read_be<uint16_t>();
    // is there enough size for the indicated padding?
    if (!stream.can_read(*opt.data_ptr())) {
        throw malformed_option();
    }
    output.key.assign(stream.pointer(), stream.pointer() + stream.size() - *opt.data_ptr());
    return output;
}

ICMPv6::handover_assist_info_type ICMPv6::handover_assist_info_type::from_option(const option& opt) {
    if (opt.data_size() < 2) {
        throw malformed_option();
    }
    const uint8_t* ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    handover_assist_info_type output;
    output.option_code = *ptr++;
    if ((end - ptr - 1) <* ptr) {
        throw malformed_option();
    }
    output.hai.assign(ptr + 1, ptr + 1 + *ptr);
    return output;
}

ICMPv6::mobile_node_id_type ICMPv6::mobile_node_id_type::from_option(const option& opt) {
    if (opt.data_size() < 2) {
        throw malformed_option();
    }
    const uint8_t* ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    mobile_node_id_type output;
    output.option_code = *ptr++;
    if ((end - ptr - 1) <* ptr) {
        throw malformed_option();
    }
    output.mn.assign(ptr + 1, ptr + 1 + *ptr);
    return output;
}

ICMPv6::dns_search_list_type ICMPv6::dns_search_list_type::from_option(const option& opt) {
    if (opt.data_size() < 2 + sizeof(uint32_t)) {
        throw malformed_option();
    }
    const uint8_t* ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    dns_search_list_type output;
    memcpy(&output.lifetime, ptr + 2, sizeof(uint32_t));
    output.lifetime = Endian::be_to_host(output.lifetime);
    ptr += 2 + sizeof(uint32_t);
    while (ptr < end && *ptr) {
        string domain;
        while (ptr < end && *ptr && *ptr < (end - ptr)) {
            if (!domain.empty()) {
                domain.push_back('.');
            }
            domain.insert(domain.end(), ptr + 1, ptr + *ptr + 1);
            ptr += *ptr + 1;
        }
        // not enough size
        if (ptr < end && *ptr != 0) {
            throw option_not_found();
        }
        output.domains.push_back(domain);
        ptr++;
    }
    return output;
}

ICMPv6::timestamp_type ICMPv6::timestamp_type::from_option(const option& opt) {
    if (opt.data_size() != 6 + sizeof(uint64_t)) {
        throw malformed_option();
    }
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    timestamp_type output;
    stream.read(output.reserved, 6);
    output.timestamp = stream.read_be<uint64_t>();
    return output;
}

ICMPv6::shortcut_limit_type ICMPv6::shortcut_limit_type::from_option(const option& opt) {
    if (opt.data_size() != 6) {
        throw malformed_option();
    }
    shortcut_limit_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.limit = stream.read<uint8_t>();
    output.reserved1 = stream.read<uint8_t>();
    output.reserved2 = stream.read_be<uint32_t>();
    return output;
}

ICMPv6::new_advert_interval_type ICMPv6::new_advert_interval_type::from_option(const option& opt) {
    if (opt.data_size() != 6) {
        throw malformed_option();
    }
    new_advert_interval_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.reserved = stream.read_be<uint16_t>();
    output.interval = stream.read_be<uint32_t>();
    return output;
}

// multicast_address_record

ICMPv6::multicast_address_record::multicast_address_record(const uint8_t* buffer, 
                                                           uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(type);
    int aux_data_len = stream.read<uint8_t>() * sizeof(uint32_t);
    int sources_count = Endian::be_to_host(stream.read<uint16_t>());
    stream.read(multicast_address);
    while (sources_count--) {
        sources.push_back(stream.read<ipaddress_type>());
    }
    if (!stream.can_read(aux_data_len)) {
        throw malformed_packet();
    }
    aux_data.assign(stream.pointer(), stream.pointer() + aux_data_len);
}

void ICMPv6::multicast_address_record::serialize(uint8_t* buffer, uint32_t total_sz) const {
    OutputMemoryStream stream(buffer, total_sz);
    stream.write(type);
    stream.write<uint8_t>(aux_data.size() / sizeof(uint32_t));
    stream.write(Endian::host_to_be<uint16_t>(sources.size()));
    stream.write(multicast_address);
    for (size_t i = 0; i < sources.size(); ++i) {
        stream.write(sources[i]);
    }
    stream.write(aux_data.begin(), aux_data.end());
}

uint32_t ICMPv6::multicast_address_record::size() const  {
    return sizeof(uint8_t) * 2 + sizeof(uint16_t) + ipaddress_type::address_size +
           sources.size() * ipaddress_type::address_size +
           aux_data.size();
}

} // Tins

