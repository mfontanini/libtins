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
 
#include <cassert>
#include <cstring>
#include "icmpv6.h"
#include "ipv6.h"
#include "rawpdu.h"
#include "utils.h"
#include "constants.h"

namespace Tins {

ICMPv6::ICMPv6(Types tp)
: _options_size()
{
    std::memset(&_header, 0, sizeof(_header));
    type(tp);
}

ICMPv6::ICMPv6(const uint8_t *buffer, uint32_t total_sz) 
: _options_size()
{
    if(total_sz < sizeof(_header))
        throw std::runtime_error("Not enough size for an ICMPv6 header");
    std::memcpy(&_header, buffer, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    if(has_target_addr()) {
        if(total_sz < ipaddress_type::address_size)
            throw std::runtime_error("Not enough size for the target address");
        target_addr(buffer);
        buffer += ipaddress_type::address_size;
        total_sz -= ipaddress_type::address_size;
    }
    if(has_dest_addr()) {
        if(total_sz < ipaddress_type::address_size)
            throw std::runtime_error("Not enough size for the destination address");
        dest_addr(buffer);
        buffer += ipaddress_type::address_size;
        total_sz -= ipaddress_type::address_size;
    }
    if(type() == ROUTER_ADVERT) {
        if(total_sz < sizeof(uint32_t) * 2)
            throw std::runtime_error("Not enough size for router advert fields");
        const uint32_t *ptr_32 = (const uint32_t*)buffer;
        reach_time = *ptr_32++;
        retrans_timer = *ptr_32++;
        
        buffer += sizeof(uint32_t) * 2;
        total_sz -= sizeof(uint32_t) * 2;
    }
    if(has_options())
        parse_options(buffer, total_sz);
    if(total_sz > 0)
        inner_pdu(new RawPDU(buffer, total_sz));
}

void ICMPv6::parse_options(const uint8_t *&buffer, uint32_t &total_sz) {
    while(total_sz > 0) {
        if(total_sz < 8 || (static_cast<uint32_t>(buffer[1]) * 8) > total_sz) 
            throw std::runtime_error("Not enough size for options");
        // size(option) = option_size - identifier_size - length_identifier_size
        add_option(icmpv6_option(buffer[0], buffer[1] * 8 - sizeof(uint8_t) * 2, buffer + 2));
        total_sz -= buffer[1] * 8;
        buffer += buffer[1] * 8;
    }
}

void ICMPv6::type(Types new_type) {
    _header.type = new_type;
}

void ICMPv6::code(uint8_t new_code) {
    _header.code = new_code;
}

void ICMPv6::checksum(uint16_t new_cksum) {
    _header.cksum = Endian::host_to_be(new_cksum);
}

void ICMPv6::identifier(uint16_t new_identifier) {
    _header.u_echo.identifier = Endian::host_to_be(new_identifier);
}

void ICMPv6::sequence(uint16_t new_sequence) {
    _header.u_echo.sequence = Endian::host_to_be(new_sequence);
}

void ICMPv6::override(small_uint<1> new_override) {
    _header.u_nd_advt.override = new_override;
}

void ICMPv6::solicited(small_uint<1> new_solicited) {
    _header.u_nd_advt.solicited = new_solicited;
}

void ICMPv6::router(small_uint<1> new_router) {
    _header.u_nd_advt.router = new_router;
}

void ICMPv6::hop_limit(uint8_t new_hop_limit) {
    _header.u_nd_ra.hop_limit = new_hop_limit;
}

void ICMPv6::router_pref(small_uint<2> new_router_pref) {
    _header.u_nd_ra.router_pref = new_router_pref;
}

void ICMPv6::home_agent(small_uint<1> new_home_agent) {
    _header.u_nd_ra.home_agent = new_home_agent;
}

void ICMPv6::other(small_uint<1> new_other) {
    _header.u_nd_ra.other = new_other;
}

void ICMPv6::managed(small_uint<1> new_managed) {
    _header.u_nd_ra.managed = new_managed;
}

void ICMPv6::router_lifetime(uint16_t new_router_lifetime) {
    _header.u_nd_ra.router_lifetime = Endian::host_to_be(new_router_lifetime);
}

void ICMPv6::reachable_time(uint32_t new_reachable_time) {
    reach_time = Endian::host_to_be(new_reachable_time);
}

void ICMPv6::retransmit_timer(uint32_t new_retrans_timer) {
    retrans_timer = Endian::host_to_be(new_retrans_timer);
}

void ICMPv6::target_addr(const ipaddress_type &new_target_addr) {
    _target_address = new_target_addr;
}

void ICMPv6::dest_addr(const ipaddress_type &new_dest_addr) {
    _dest_address = new_dest_addr;
}

uint32_t ICMPv6::header_size() const {
    return sizeof(_header) + _options_size + 
        (has_target_addr() ? ipaddress_type::address_size : 0) +
        (has_dest_addr() ? ipaddress_type::address_size : 0);
}

void ICMPv6::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    #ifdef TINS_DEBUG
    assert(total_sz >= header_size());
    #endif
    icmp6hdr* ptr_header = (icmp6hdr*)buffer;
    std::memcpy(buffer, &_header, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    if(has_target_addr()) {
        buffer = _target_address.copy(buffer);
        total_sz -= sizeof(ipaddress_type::address_size);
    }
    if(has_dest_addr()) {
        buffer = _dest_address.copy(buffer);
        total_sz -= sizeof(ipaddress_type::address_size);
    }
    for(options_type::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        #ifdef TINS_DEBUG
        assert(total_sz >= it->data_size() + sizeof(uint8_t) * 2);
        total_sz -= it->data_size() + sizeof(uint8_t) * 2;
        #endif
        buffer = write_option(*it, buffer);
    }
    if(!_header.cksum) {
        const Tins::IPv6 *ipv6 = dynamic_cast<const Tins::IPv6*>(parent);
        if(ipv6) {
            uint32_t checksum = Utils::pseudoheader_checksum(
                                    ipv6->src_addr(),  
                                    ipv6->dst_addr(), 
                                    size(), 
                                    Constants::IP::PROTO_ICMPV6
                                ) + Utils::do_checksum((uint8_t*)ptr_header, buffer);
            while (checksum >> 16) 
                checksum = (checksum & 0xffff) + (checksum >> 16);
            ptr_header->cksum = Endian::host_to_be<uint16_t>(~checksum);
        }
    }
}

// can i haz more?
bool ICMPv6::has_options() const {
    return type() == NEIGHBOUR_SOLICIT ||
            type() == ROUTER_ADVERT;
}

void ICMPv6::add_option(const icmpv6_option &option) {
    _options.push_back(option);
    _options_size += option.data_size() + sizeof(uint8_t) * 2;
}

uint8_t *ICMPv6::write_option(const icmpv6_option &opt, uint8_t *buffer) {
    *buffer++ = opt.option();
    *buffer++ = (opt.data_size() + sizeof(uint8_t) * 2) / 8;
    return std::copy(opt.data_ptr(), opt.data_ptr() + opt.data_size(), buffer);
}

const ICMPv6::icmpv6_option *ICMPv6::search_option(Options id) const {
    for(options_type::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        if(it->option() == id)
            return &*it;
    }
    return 0;
}

// Option setters

void ICMPv6::source_link_layer_addr(const hwaddress_type &addr) {
    add_option(icmpv6_option(SOURCE_ADDRESS, addr.begin(), addr.end()));
}

void ICMPv6::target_link_layer_addr(const hwaddress_type &addr) {
    add_option(icmpv6_option(TARGET_ADDRESS, addr.begin(), addr.end()));
}

void ICMPv6::prefix_info(prefix_info_type info) {
    info.valid_lifetime = Endian::host_to_be(info.valid_lifetime);
    info.preferred_lifetime = Endian::host_to_be(info.preferred_lifetime);
    add_option(
        icmpv6_option(PREFIX_INFO, sizeof(prefix_info_type), (const uint8_t*)&info)
    );
}

void ICMPv6::redirect_header(PDU::serialization_type data) {
    // Reserved fields
    data.insert(data.begin(), 6, 0);
    // Padding(if necessary)
    uint8_t padding = 8 - (data.size() + sizeof(uint8_t) * 2) % 8;
    if(padding == 8)
        padding = 0;
    data.insert(data.end(), padding, 0);
    add_option(icmpv6_option(REDIRECT_HEADER, data.begin(), data.end()));
}

void ICMPv6::mtu(uint32_t value) {
    uint8_t buffer[sizeof(uint16_t) + sizeof(uint32_t)] = {0};
    *((uint32_t*)(buffer + sizeof(uint16_t))) = Endian::host_to_be(value);
    add_option(icmpv6_option(MTU, sizeof(buffer), buffer));
}

void ICMPv6::shortcut_limit(uint8_t value) {
    uint8_t buffer[sizeof(uint16_t) + sizeof(uint32_t)] = {0};
    buffer[0] = value;
    add_option(icmpv6_option(NBMA_SHORT_LIMIT, sizeof(buffer), buffer));
}

void ICMPv6::new_advert_interval(uint32_t value) {
    uint8_t buffer[sizeof(uint16_t) + sizeof(uint32_t)] = {0};
    *((uint32_t*)(buffer + sizeof(uint16_t))) = Endian::host_to_be(value);
    add_option(icmpv6_option(ADVERT_INTERVAL, sizeof(buffer), buffer));
}

void ICMPv6::new_home_agent_info(const new_ha_info_type &value) {
    uint8_t buffer[sizeof(uint16_t) + sizeof(uint32_t)] = {0};
    *((uint16_t*)(buffer + sizeof(uint16_t))) = Endian::host_to_be(value.first);
    *((uint16_t*)(buffer + sizeof(uint16_t) * 2)) = Endian::host_to_be(value.second);
    add_option(icmpv6_option(HOME_AGENT_INFO, sizeof(buffer), buffer));
}

// Option getters

ICMPv6::hwaddress_type ICMPv6::source_link_layer_addr() const {
    const icmpv6_option *opt = search_option(SOURCE_ADDRESS);
    if(!opt || opt->data_size() != hwaddress_type::address_size)
        throw option_not_found();
    return hwaddress_type(opt->data_ptr());
}

ICMPv6::hwaddress_type ICMPv6::target_link_layer_addr() const {
    const icmpv6_option *opt = search_option(TARGET_ADDRESS);
    if(!opt || opt->data_size() != hwaddress_type::address_size)
        throw option_not_found();
    return hwaddress_type(opt->data_ptr());
}

ICMPv6::prefix_info_type ICMPv6::prefix_info() const {
    const icmpv6_option *opt = search_option(PREFIX_INFO);
    if(!opt || opt->data_size() != sizeof(prefix_info_type))
        throw option_not_found();
    prefix_info_type output;
    std::memcpy(&output, opt->data_ptr(), sizeof(prefix_info_type));
    output.valid_lifetime = Endian::be_to_host(output.valid_lifetime);
    output.preferred_lifetime = Endian::be_to_host(output.preferred_lifetime);
    return output;
}

PDU::serialization_type ICMPv6::redirect_header() const {
    const icmpv6_option *opt = search_option(REDIRECT_HEADER);
    if(!opt || opt->data_size() < 6)
        throw option_not_found();
    const uint8_t *ptr = opt->data_ptr() + 6;
    return serialization_type(ptr, ptr + opt->data_size() - 6);
}

uint32_t ICMPv6::mtu() const {
    const icmpv6_option *opt = search_option(MTU);
    if(!opt || opt->data_size() != sizeof(uint16_t) + sizeof(uint32_t))
        throw option_not_found();
    return Endian::be_to_host(*(const uint32_t*)(opt->data_ptr() + sizeof(uint16_t)));
}

uint8_t ICMPv6::shortcut_limit() const {
    const icmpv6_option *opt = search_option(NBMA_SHORT_LIMIT);
    if(!opt || opt->data_size() != sizeof(uint16_t) + sizeof(uint32_t))
        throw option_not_found();
    return *opt->data_ptr();
}

uint32_t ICMPv6::new_advert_interval() const {
    const icmpv6_option *opt = search_option(ADVERT_INTERVAL);
    if(!opt || opt->data_size() != sizeof(uint16_t) + sizeof(uint32_t))
        throw option_not_found();
    return Endian::be_to_host(*(const uint32_t*)(opt->data_ptr() + sizeof(uint16_t)));
}

ICMPv6::new_ha_info_type ICMPv6::new_home_agent_info() const {
    const icmpv6_option *opt = search_option(HOME_AGENT_INFO);
    if(!opt || opt->data_size() != sizeof(uint16_t) + sizeof(uint32_t))
        throw option_not_found();
    return std::make_pair(
        Endian::be_to_host(*(const uint16_t*)(opt->data_ptr() + sizeof(uint16_t))),
        Endian::be_to_host(*(const uint16_t*)(opt->data_ptr() + sizeof(uint16_t) * 2))
    );
}
}

