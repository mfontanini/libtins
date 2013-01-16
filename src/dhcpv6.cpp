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

const DHCPv6::dhcpv6_option *DHCPv6::search_option(uint16_t id) const {
    for(options_type::const_iterator it = options_.begin(); it != options_.end(); ++it) {
        if(it->option() == id)
            return &*it;
    }
    return 0;
}

uint8_t* DHCPv6::write_option(const dhcpv6_option &option, uint8_t* buffer) const {
    *(uint16_t*)buffer = Endian::host_to_be(option.option());
    *(uint16_t*)&buffer[sizeof(uint16_t)] = Endian::host_to_be(option.data_size());
    std::cout << "Size: " << option.data_size() << std::endl;
    return std::copy(
        option.data_ptr(), 
        option.data_ptr() + option.data_size(), 
        buffer + sizeof(uint16_t) * 2
    );
}
    
void DHCPv6::msg_type(uint8_t type) {
    header_data[0] = type;
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
}
