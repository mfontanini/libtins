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
#include "endianness.h"
#include "dhcp.h"
#include "ethernetII.h"
#include "internals.h"
#include "exceptions.h"
#include "memory_helpers.h"

using std::string;
using std::vector;
using std::list;
using std::runtime_error;
using std::find_if;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PDU::metadata DHCP::extract_metadata(const uint8_t *buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(bootp_header))) {
        throw malformed_packet();
    }
    return metadata(total_sz, pdu_flag, PDU::UNKNOWN);
}

// Magic cookie: uint32_t. 
DHCP::DHCP() 
: size_(sizeof(uint32_t)) {
    opcode(BOOTREQUEST);
    htype(1); //ethernet
    hlen(EthernetII::address_type::address_size);
}

DHCP::DHCP(const uint8_t* buffer, uint32_t total_sz) 
: BootP(buffer, total_sz, 0), size_(sizeof(uint32_t)) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(BootP::header_size() - vend().size());
    const uint32_t magic_number = stream.read<uint32_t>();
    if (magic_number != Endian::host_to_be<uint32_t>(0x63825363)) {
        throw malformed_packet();
    }
    // While there's data left
    while (stream) {
        OptionTypes option_type;
        uint8_t option_length = 0;
        option_type = (OptionTypes)stream.read<uint8_t>();
        // We should only read the length if it's not END nor PAD
        if (option_type != END && option_type != PAD) {
            option_length = stream.read<uint8_t>();
        }
        // Make sure we can read the payload size
        if (!stream.can_read(option_length)) {
            throw malformed_packet();
        }
        add_option(option(option_type, option_length, stream.pointer()));
        stream.skip(option_length);
    }
}

void DHCP::add_option(const option& opt) {
    internal_add_option(opt);
    options_.push_back(opt);
}

void DHCP::internal_add_option(const option& opt) {
    size_ += static_cast<uint32_t>(opt.data_size() + (sizeof(uint8_t) << 1));
}

bool DHCP::remove_option(OptionTypes type) {
    options_type::iterator iter = search_option_iterator(type);
    if (iter == options_.end()) {
        return false;
    }
    size_ -= static_cast<uint32_t>(iter->data_size() + (sizeof(uint8_t) << 1));
    options_.erase(iter);
    return true;
}

const DHCP::option* DHCP::search_option(OptionTypes opt) const {
    // Search for the iterator. If we found something, return it, otherwise return nullptr.
    options_type::const_iterator iter = search_option_iterator(opt);
    return (iter != options_.end()) ? &*iter : 0;
}

DHCP::options_type::const_iterator DHCP::search_option_iterator(OptionTypes opt) const {
    Internals::option_type_equality_comparator<option> comparator(opt);
    return find_if(options_.begin(), options_.end(), comparator);
}

DHCP::options_type::iterator DHCP::search_option_iterator(OptionTypes opt) {
    Internals::option_type_equality_comparator<option> comparator(opt);
    return find_if(options_.begin(), options_.end(), comparator);
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

void DHCP::routers(const vector<ipaddress_type>& routers) {
    serialization_type buffer = serialize_list(routers);
    add_option(option(ROUTERS, buffer.begin(), buffer.end()));
}

vector<DHCP::ipaddress_type> DHCP::routers() const {
    return search_and_convert<vector<DHCP::ipaddress_type> >(ROUTERS);
}

void DHCP::domain_name_servers(const vector<ipaddress_type>& dns) {
    serialization_type buffer = serialize_list(dns);
    add_option(option(DOMAIN_NAME_SERVERS, buffer.begin(), buffer.end()));
}

vector<DHCP::ipaddress_type> DHCP::domain_name_servers() const {
    return search_and_convert<vector<DHCP::ipaddress_type> >(DOMAIN_NAME_SERVERS);
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

void DHCP::domain_name(const string& name) {
    add_option(option(DOMAIN_NAME, name.size(), (const uint8_t*)name.c_str()));
}

string DHCP::domain_name() const {
    return search_and_convert<string>(DOMAIN_NAME);
}

void DHCP::hostname(const string& name) {
    add_option(option(HOST_NAME, name.size(), (const uint8_t*)name.c_str()));
}

string DHCP::hostname() const {
    return search_and_convert<string>(HOST_NAME);
}

void DHCP::rebind_time(uint32_t time) {
    time = Endian::host_to_be(time);
    add_option(option(DHCP_REBINDING_TIME, sizeof(uint32_t), (uint8_t*)&time));
}
        
uint32_t DHCP::rebind_time() const {
    return search_and_convert<uint32_t>(DHCP_REBINDING_TIME);
}

PDU::serialization_type DHCP::serialize_list(const vector<ipaddress_type>& ip_list) {
    serialization_type buffer(ip_list.size() * sizeof(uint32_t));
    uint32_t* ptr = (uint32_t*)&buffer[0];
    typedef vector<ipaddress_type>::const_iterator iterator;
    for (iterator it = ip_list.begin(); it != ip_list.end(); ++it) {
        *(ptr++) = *it;
    }
    return buffer;
}

uint32_t DHCP::header_size() const {
    return static_cast<uint32_t>(BootP::header_size() - vend().size() + size_);
}

void DHCP::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent) {
    if (size_) {
        vend_type& result = BootP::vend();
        result.resize(size_);
        // Build a stream over the vend vector
        OutputMemoryStream stream(&result[0], result.size());
        // Magic cookie
        stream.write(Endian::host_to_be<uint32_t>(0x63825363));
        for (options_type::const_iterator it = options_.begin(); it != options_.end(); ++it) {
            stream.write(it->option());
            stream.write<uint8_t>(it->length_field());
            stream.write(it->data_ptr(), it->data_size());
        }
    }
    BootP::write_serialization(buffer, total_sz, parent);
}

} // Tins
