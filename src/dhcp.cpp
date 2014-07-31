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
#include <cassert>
#include <cstring>
#include "endianness.h"
#include "dhcp.h"
#include "ethernetII.h"
#include "exceptions.h"

using std::string;
using std::list;
using std::runtime_error;

namespace Tins {
// Magic cookie: uint32_t. 
DHCP::DHCP() : _size(sizeof(uint32_t)) {
    opcode(BOOTREQUEST);
    htype(1); //ethernet
    hlen(EthernetII::address_type::address_size);
}

DHCP::DHCP(const uint8_t *buffer, uint32_t total_sz) 
: BootP(buffer, total_sz, 0), _size(sizeof(uint32_t))
{
    buffer += BootP::header_size() - vend().size();
    total_sz -= BootP::header_size() - vend().size();
    uint8_t args[2] = {0};
    uint32_t uint32_t_buffer;
    std::memcpy(&uint32_t_buffer, buffer, sizeof(uint32_t));
    if(total_sz < sizeof(uint32_t) || uint32_t_buffer != Endian::host_to_be<uint32_t>(0x63825363))
        throw malformed_packet();
    buffer += sizeof(uint32_t);
    total_sz -= sizeof(uint32_t);
    while(total_sz) {
        for(unsigned i(0); i < 2; ++i) {
            args[i] = *(buffer++);
            total_sz--;
            if(args[0] == END || args[0] == PAD) {
                args[1] = 0;
                i = 2;
            }
            else if(!total_sz)
                throw malformed_packet();
        }
        if(total_sz < args[1])
            throw malformed_packet();
        add_option(
            option((OptionTypes)args[0], args[1], buffer)
        );
        buffer += args[1];
        total_sz -= args[1];
    }
}

void DHCP::add_option(const option &opt) {
    internal_add_option(opt);
    _options.push_back(opt);
}

void DHCP::internal_add_option(const option &opt) {
    _size += opt.data_size() + (sizeof(uint8_t) << 1);
}

const DHCP::option *DHCP::search_option(OptionTypes opt) const {
    for(options_type::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        if(it->option() == opt)
            return &(*it);
    }
    return 0;
}

void DHCP::type(Flags type) {
    uint8_t int_type = type;
    add_option(option(DHCP_MESSAGE_TYPE, sizeof(uint8_t), &int_type));
}

void DHCP::end() {
    add_option(option(END));
}

uint8_t DHCP::type() const {
    return search_and_convert<uint8_t>(DHCP_MESSAGE_TYPE);
}

void DHCP::server_identifier(ipaddress_type ip) {
    uint32_t ip_int = ip;
    add_option(option(DHCP_SERVER_IDENTIFIER, sizeof(uint32_t), (const uint8_t*)&ip_int));
}

DHCP::ipaddress_type DHCP::server_identifier() const {
    return search_and_convert<ipaddress_type>(DHCP_SERVER_IDENTIFIER);
}

void DHCP::lease_time(uint32_t time) {
    time = Endian::host_to_be(time);
    add_option(option(DHCP_LEASE_TIME, sizeof(uint32_t), (const uint8_t*)&time));
}

uint32_t DHCP::lease_time() const {
    return search_and_convert<uint32_t>(DHCP_LEASE_TIME);
}

void DHCP::renewal_time(uint32_t time) {
    time = Endian::host_to_be(time);
    add_option(option(DHCP_RENEWAL_TIME, sizeof(uint32_t), (const uint8_t*)&time));
}
        
uint32_t DHCP::renewal_time() const {
    return search_and_convert<uint32_t>(DHCP_RENEWAL_TIME);
}

void DHCP::subnet_mask(ipaddress_type mask) {
    uint32_t mask_int = mask;
    add_option(option(SUBNET_MASK, sizeof(uint32_t), (const uint8_t*)&mask_int));
}

DHCP::ipaddress_type DHCP::subnet_mask() const {
    return search_and_convert<ipaddress_type>(SUBNET_MASK);
}

void DHCP::routers(const std::vector<ipaddress_type> &routers) {
    serialization_type buffer = serialize_list(routers);
    add_option(option(ROUTERS, buffer.begin(), buffer.end()));
}

std::vector<DHCP::ipaddress_type> DHCP::routers() const {
    return search_and_convert<std::vector<DHCP::ipaddress_type> >(ROUTERS);
}

void DHCP::domain_name_servers(const std::vector<ipaddress_type> &dns) {
    serialization_type buffer = serialize_list(dns);
    add_option(option(DOMAIN_NAME_SERVERS, buffer.begin(), buffer.end()));
}

std::vector<DHCP::ipaddress_type> DHCP::domain_name_servers() const {
    return search_and_convert<std::vector<DHCP::ipaddress_type> >(DOMAIN_NAME_SERVERS);
}

void DHCP::broadcast(ipaddress_type addr) {
    uint32_t int_addr = addr;
    add_option(option(BROADCAST_ADDRESS, sizeof(uint32_t), (uint8_t*)&int_addr));
}

DHCP::ipaddress_type DHCP::broadcast() const {
    return search_and_convert<ipaddress_type>(BROADCAST_ADDRESS);
}

void DHCP::requested_ip(ipaddress_type addr) {
    uint32_t int_addr = addr;
    add_option(option(DHCP_REQUESTED_ADDRESS, sizeof(uint32_t), (uint8_t*)&int_addr));
}

DHCP::ipaddress_type DHCP::requested_ip() const {
    return search_and_convert<ipaddress_type>(DHCP_REQUESTED_ADDRESS);
}

void DHCP::domain_name(const string &name) {
    add_option(option(DOMAIN_NAME, name.size(), (const uint8_t*)name.c_str()));
}

std::string DHCP::domain_name() const {
    return search_and_convert<std::string>(DOMAIN_NAME);
}

void DHCP::hostname(const std::string &name) {
    add_option(option(HOST_NAME, name.size(), (const uint8_t*)name.c_str()));
}

std::string DHCP::hostname() const {
    return search_and_convert<std::string>(HOST_NAME);
}

void DHCP::rebind_time(uint32_t time) {
    time = Endian::host_to_be(time);
    add_option(option(DHCP_REBINDING_TIME, sizeof(uint32_t), (uint8_t*)&time));
}
        
uint32_t DHCP::rebind_time() const {
    return search_and_convert<uint32_t>(DHCP_REBINDING_TIME);
}

PDU::serialization_type DHCP::serialize_list(const std::vector<ipaddress_type> &ip_list) {
    serialization_type buffer(ip_list.size() * sizeof(uint32_t));
    uint32_t *ptr = (uint32_t*)&buffer[0];
    for(std::vector<ipaddress_type>::const_iterator it = ip_list.begin(); it != ip_list.end(); ++it)
        *(ptr++) = *it;
    return buffer;
}

uint32_t DHCP::header_size() const {
    return BootP::header_size() - vend().size() + _size;
}

void DHCP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    #ifdef TINS_DEBUG
    assert(total_sz >= header_size());
    #endif
    if(_size) {
        vend_type &result(BootP::vend());
        result.resize(_size);
        uint8_t *ptr = &result[0] + sizeof(uint32_t);
        // Magic cookie
        *((uint32_t*)&result[0]) = Endian::host_to_be<uint32_t>(0x63825363);
        for(options_type::const_iterator it = _options.begin(); it != _options.end(); ++it) {
            *(ptr++) = it->option();
            *(ptr++) = it->length_field();
            std::copy(it->data_ptr(), it->data_ptr() + it->data_size(), ptr);
            ptr += it->data_size();
        }
    }
    BootP::write_serialization(buffer, total_sz, parent);
}
}
