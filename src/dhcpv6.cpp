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

#include <iostream>  //borrame
#include <vector>
#include <algorithm>
#include "dhcpv6.h"

namespace Tins {
DHCPv6::DHCPv6() : options_size() {
    std::fill(header_data, header_data + sizeof(header_data), 0);
}

DHCPv6::DHCPv6(const uint8_t *buffer, uint32_t total_sz) 
: options_size() 
{
    const char *err_msg = "Not enough size for a DHCPv6 header",
                *opt_err_msg = "Not enough size for a DHCPv6 option";
    if(total_sz == 0) 
        throw std::runtime_error(err_msg);
    // Relay Agent/Server Messages
    bool is_relay_msg = (buffer[0] == 12 || buffer[0] == 13);
    uint32_t required_size = is_relay_msg ? 2 : 4;
    if(total_sz < required_size)
        throw std::runtime_error(err_msg);
    std::copy(buffer, buffer + required_size, header_data);
    buffer += required_size;
    total_sz -= required_size;
    if(is_relay_message()) {
        if(total_sz < ipaddress_type::address_size * 2)
            throw std::runtime_error(err_msg);
        link_addr = buffer;
        peer_addr = buffer + ipaddress_type::address_size;
        buffer += ipaddress_type::address_size * 2;
        total_sz -= ipaddress_type::address_size * 2;
    }
    options_size = total_sz;
    while(total_sz) {
        if(total_sz < sizeof(uint16_t) * 2) 
            throw std::runtime_error(opt_err_msg);
        
        const uint16_t option = Endian::be_to_host(*(const uint16_t*)buffer);
        const uint16_t data_size = Endian::be_to_host(
            *(const uint16_t*)(buffer + sizeof(uint16_t))
        );
        if(total_sz - sizeof(uint16_t) * 2 < data_size)
            throw std::runtime_error(opt_err_msg);
        buffer += sizeof(uint16_t) * 2;
        add_option(
            dhcpv6_option(option, buffer, buffer + data_size)
        );
        buffer += data_size;
        total_sz -= sizeof(uint16_t) * 2 + data_size;
    }
}
    
void DHCPv6::add_option(const dhcpv6_option &option) {
    options_.push_back(option);
}

const DHCPv6::dhcpv6_option *DHCPv6::search_option(Option id) const {
    for(options_type::const_iterator it = options_.begin(); it != options_.end(); ++it) {
        if(it->option() == static_cast<uint16_t>(id))
            return &*it;
    }
    return 0;
}

uint8_t* DHCPv6::write_option(const dhcpv6_option &option, uint8_t* buffer) const {
    *(uint16_t*)buffer = Endian::host_to_be(option.option());
    *(uint16_t*)&buffer[sizeof(uint16_t)] = Endian::host_to_be(option.data_size());
    return std::copy(
        option.data_ptr(), 
        option.data_ptr() + option.data_size(), 
        buffer + sizeof(uint16_t) * 2
    );
}
    
void DHCPv6::msg_type(MessageType type) {
    header_data[0] = static_cast<uint8_t>(type);
}

void DHCPv6::hop_count(uint8_t count) {
    header_data[1] = count;
}

void DHCPv6::transaction_id(small_uint<24> id) {
    uint32_t id_32 = id;
    header_data[1] = id_32 >> 16;
    header_data[2] = id_32 >> 8;
    header_data[3] = id_32 & 0xff;
}

void DHCPv6::peer_address(const ipaddress_type &addr) {
    peer_addr = addr;
}

void DHCPv6::link_address(const ipaddress_type &addr) {
    link_addr = addr;
}

bool DHCPv6::is_relay_message() const {
    return msg_type() == 12 || msg_type() == 13;
}

uint32_t DHCPv6::header_size() const {
    return (is_relay_message() ? (2 + ipaddress_type::address_size * 2) : 4) + options_size;
}

void DHCPv6::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    const uint32_t required_size = is_relay_message() ? 2 : 4;
    buffer = std::copy(header_data, header_data + required_size, buffer);
    if(is_relay_message()) {
        buffer = link_addr.copy(buffer);
        buffer = peer_addr.copy(buffer);
    }
    for(options_type::const_iterator it = options_.begin(); it != options_.end(); ++it)
        buffer = write_option(*it, buffer);
}


// ********************************************************************
//                          Option getters
// ********************************************************************

DHCPv6::ia_na_type DHCPv6::ia_na() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        IA_NA, sizeof(uint32_t) * 3
    );
    const uint8_t *ptr = opt->data_ptr() + sizeof(uint32_t) * 3;
    const uint32_t *ptr_32 = (const uint32_t*)opt->data_ptr();
    DHCPv6::ia_na_type output;
    output.id = Endian::be_to_host(*ptr_32++);
    output.t1 = Endian::be_to_host(*ptr_32++);
    output.t2 = Endian::be_to_host(*ptr_32++);
    output.options.assign(ptr, opt->data_ptr() + opt->data_size());
    return output;
}

DHCPv6::ia_ta_type DHCPv6::ia_ta() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        IA_TA, sizeof(uint32_t)
    );
    const uint8_t *ptr = opt->data_ptr() + sizeof(uint32_t);
    const uint32_t *ptr_32 = (const uint32_t*)opt->data_ptr();
    DHCPv6::ia_ta_type output;
    output.id = Endian::be_to_host(*ptr_32++);
    output.options.assign(ptr, opt->data_ptr() + opt->data_size());
    return output;
}

DHCPv6::ia_address_type DHCPv6::ia_address() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        IA_ADDR, sizeof(uint32_t) * 2 + ipaddress_type::address_size
    );
    const uint8_t *ptr = opt->data_ptr() + sizeof(uint32_t) * 2 + ipaddress_type::address_size;
    const uint32_t *ptr_32 = (const uint32_t*)(opt->data_ptr() + ipaddress_type::address_size);
    DHCPv6::ia_address_type output;
    output.address = opt->data_ptr();
    output.preferred_lifetime = Endian::be_to_host(*ptr_32++);
    output.valid_lifetime = Endian::be_to_host(*ptr_32++);
    output.options.assign(ptr, opt->data_ptr() + opt->data_size());
    return output;
}

DHCPv6::option_request_type DHCPv6::option_request() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        OPTION_REQUEST, 2
    );
    const uint16_t *ptr = (const uint16_t*)opt->data_ptr(), 
                    *end = (const uint16_t*)(opt->data_ptr() + opt->data_size());
    option_request_type output;
    while(ptr < end) {
        output.push_back(
            static_cast<Option>(Endian::be_to_host(*ptr++))
        );
    }
    return output;
}

uint8_t DHCPv6::preference() const {
    const dhcpv6_option *opt = safe_search_option<std::not_equal_to>(
        PREFERENCE, 1
    );
    return *opt->data_ptr();
}

uint16_t DHCPv6::elapsed_time() const {
    const dhcpv6_option *opt = safe_search_option<std::not_equal_to>(
        ELAPSED_TIME, 2
    );
    return Endian::be_to_host(
        *(const uint16_t*)opt->data_ptr()
    );
}

DHCPv6::relay_msg_type DHCPv6::relay_message() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        RELAY_MSG, 1
    );
    return relay_msg_type(
        opt->data_ptr(), 
        opt->data_ptr() + opt->data_size()
    );
}

DHCPv6::authentication_type DHCPv6::authentication() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        AUTH, sizeof(uint8_t) * 3 + sizeof(uint64_t)
    );
    const uint8_t *ptr = opt->data_ptr();
    authentication_type output;
    output.protocol = *ptr++;
    output.algorithm = *ptr++;
    output.rdm = *ptr++;
    output.replay_detection = Endian::be_to_host(
        *(const uint64_t*)ptr
    );
    ptr += sizeof(uint64_t);
    output.auth_info.assign(ptr, opt->data_ptr() + opt->data_size());
    return output;
}

DHCPv6::ipaddress_type DHCPv6::server_unicast() const {
    const dhcpv6_option *opt = safe_search_option<std::not_equal_to>(
        UNICAST, ipaddress_type::address_size
    );
    return ipaddress_type(opt->data_ptr());
}

DHCPv6::status_code_type DHCPv6::status_code() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        STATUS_CODE, sizeof(uint16_t)
    );
    status_code_type output;
    output.code = Endian::be_to_host(*(const uint16_t*)opt->data_ptr());
    output.message.assign(
        opt->data_ptr() + sizeof(uint16_t),
        opt->data_ptr() + opt->data_size()
    );
    return output;
}

bool DHCPv6::has_rapid_commit() const {
    return search_option(RAPID_COMMIT);
}

DHCPv6::user_class_type DHCPv6::user_class() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        USER_CLASS, sizeof(uint16_t)
    );
    return option2class_option_data<user_class_type>(
        opt->data_ptr(), opt->data_size()
    );
}

DHCPv6::vendor_class_type DHCPv6::vendor_class() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        VENDOR_CLASS, sizeof(uint32_t)
    );
    typedef vendor_class_type::class_data_type data_type;
    vendor_class_type output;
    output.enterprise_number = Endian::be_to_host(
        *(const uint32_t*)opt->data_ptr()
    );
    output.vendor_class_data = option2class_option_data<data_type>(
        opt->data_ptr() + sizeof(uint32_t),
        opt->data_size() - sizeof(uint32_t)
    );
    
    return output;
}

DHCPv6::vendor_info_type DHCPv6::vendor_info() const {
    const dhcpv6_option *opt = safe_search_option<std::less>(
        VENDOR_OPTS, sizeof(uint32_t)
    );
    vendor_info_type output;
    output.enterprise_number = Endian::be_to_host(
        *(const uint32_t*)opt->data_ptr()
    );
    output.data.assign(
        opt->data_ptr() + sizeof(uint32_t),
        opt->data_ptr() + opt->data_size()
    );
    return output;
}

DHCPv6::interface_id_type DHCPv6::interface_id() const {
    const dhcpv6_option *opt = safe_search_option<std::equal_to>(
        INTERFACE_ID, 0
    );
    return interface_id_type(
        opt->data_ptr(),
        opt->data_ptr() + opt->data_size()
    );
}

uint8_t DHCPv6::reconfigure_msg() const {
    return *safe_search_option<std::not_equal_to>(
        RECONF_MSG, 1
    )->data_ptr();
}

bool DHCPv6::has_reconfigure_accept() const {
    return search_option(RECONF_ACCEPT);
}

// ********************************************************************
//                          Option setters
// ********************************************************************

void DHCPv6::ia_na(const ia_na_type &value) {
    std::vector<uint8_t> buffer(sizeof(uint32_t) * 3 + value.options.size());
    uint32_t *ptr = (uint32_t*)&buffer[0];
    *ptr++ = Endian::host_to_be(value.id);
    *ptr++ = Endian::host_to_be(value.t1);
    *ptr++ = Endian::host_to_be(value.t2);
    std::copy(
        value.options.begin(), 
        value.options.end(), 
        buffer.begin() + sizeof(uint32_t) * 3
    );
    add_option(
        dhcpv6_option(IA_NA, buffer.begin(), buffer.end())
    );
}

void DHCPv6::ia_ta(const ia_ta_type &value) {
    std::vector<uint8_t> buffer(sizeof(uint32_t) + value.options.size());
    uint32_t *ptr = (uint32_t*)&buffer[0];
    *ptr++ = Endian::host_to_be(value.id);
    std::copy(
        value.options.begin(), 
        value.options.end(), 
        buffer.begin() + sizeof(uint32_t)
    );
    add_option(
        dhcpv6_option(IA_TA, buffer.begin(), buffer.end())
    );
}

void DHCPv6::ia_address(const ia_address_type &value) {
    std::vector<uint8_t> buffer(
        sizeof(uint32_t) * 2 + ipaddress_type::address_size + value.options.size()
    );
    uint32_t *ptr = (uint32_t*)&buffer[ipaddress_type::address_size];
    value.address.copy(&buffer[0]);
    *ptr++ = Endian::host_to_be(value.preferred_lifetime);
    *ptr++ = Endian::host_to_be(value.valid_lifetime);
    std::copy(
        value.options.begin(), 
        value.options.end(), 
        buffer.begin() + sizeof(uint32_t) * 2 + ipaddress_type::address_size
    );
    add_option(
        dhcpv6_option(IA_ADDR, buffer.begin(), buffer.end())
    );
}

void DHCPv6::option_request(const option_request_type &value) {
    typedef option_request_type::const_iterator iterator;
    
    std::vector<uint8_t> buffer(value.size() * sizeof(uint16_t));
    size_t index = 0;
    for(iterator it = value.begin(); it != value.end(); ++it, index += 2) 
        *(uint16_t*)&buffer[index] = Endian::host_to_be<uint16_t>(*it);
    add_option(
        dhcpv6_option(OPTION_REQUEST, buffer.begin(), buffer.end())
    );
}

void DHCPv6::preference(uint8_t value) {
    add_option(
        dhcpv6_option(PREFERENCE, 1, &value)
    );
}

void DHCPv6::elapsed_time(uint16_t value) {
    value = Endian::host_to_be(value);
    add_option(
        dhcpv6_option(ELAPSED_TIME, 2, (const uint8_t*)&value)
    );
}

void DHCPv6::relay_message(const relay_msg_type &value) {
    add_option(
        dhcpv6_option(RELAY_MSG, value.begin(), value.end())
    );
}

void DHCPv6::authentication(const authentication_type &value) {
    std::vector<uint8_t> buffer(
        sizeof(uint8_t) * 3 + sizeof(uint64_t) + value.auth_info.size()
    );
    buffer[0] = value.protocol;
    buffer[1] = value.algorithm;
    buffer[2] = value.rdm;
    *(uint64_t*)&buffer[3] = Endian::host_to_be(value.replay_detection);
    std::copy(
        value.auth_info.begin(), 
        value.auth_info.end(),
        buffer.begin() + sizeof(uint8_t) * 3 + sizeof(uint64_t)
    );
    add_option(
        dhcpv6_option(AUTH, buffer.begin(), buffer.end())
    );
}

void DHCPv6::server_unicast(const ipaddress_type &value) {
    add_option(
        dhcpv6_option(UNICAST, value.begin(), value.end())
    );
}

void DHCPv6::status_code(const status_code_type &value) {
    std::vector<uint8_t> buffer(sizeof(uint16_t) + value.message.size());
    *(uint16_t*)&buffer[0] = Endian::host_to_be(value.code);
    std::copy(
        value.message.begin(), 
        value.message.end(), 
        buffer.begin() + sizeof(uint16_t)
    );
    add_option(
        dhcpv6_option(STATUS_CODE, buffer.begin(), buffer.end())
    );
}

void DHCPv6::rapid_commit() {
    add_option(
        RAPID_COMMIT
    );
}

void DHCPv6::user_class(const user_class_type &value) {
    typedef user_class_type::const_iterator iterator;
    
    std::vector<uint8_t> buffer;
    class_option_data2option(value.begin(), value.end(), buffer);
    add_option(
        dhcpv6_option(USER_CLASS, buffer.begin(), buffer.end())
    );
}

void DHCPv6::vendor_class(const vendor_class_type &value) {
    std::vector<uint8_t> buffer(
        sizeof(uint32_t)
    );
    *(uint32_t*)&buffer[0] = Endian::host_to_be(value.enterprise_number);
    class_option_data2option(
        value.vendor_class_data.begin(),
        value.vendor_class_data.end(),
        buffer,
        sizeof(uint32_t)
    );
    add_option(
        dhcpv6_option(VENDOR_CLASS, buffer.begin(), buffer.end())
    );
}

void DHCPv6::vendor_info(const vendor_info_type &value) {
    std::vector<uint8_t> buffer(sizeof(uint32_t) + value.data.size());
    *(uint32_t*)&buffer[0] = Endian::host_to_be(value.enterprise_number);
    std::copy(
        value.data.begin(),
        value.data.end(),
        buffer.begin() + sizeof(uint32_t)
    );
    add_option(
        dhcpv6_option(VENDOR_OPTS, buffer.begin(), buffer.end())
    );
}

void DHCPv6::interface_id(const interface_id_type &value) {
    add_option(
        dhcpv6_option(INTERFACE_ID, value.begin(), value.end())
    );
}

void DHCPv6::reconfigure_msg(uint8_t value) {
    add_option(
        dhcpv6_option(RECONF_MSG, 1, &value)
    );
}

void DHCPv6::reconfigure_accept() {
    add_option(RECONF_ACCEPT);
}
} // namespace Tins
