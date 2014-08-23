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

#include <vector>
#include <algorithm>
#include "dhcpv6.h"
#include "exceptions.h"

namespace Tins {
DHCPv6::DHCPv6() : options_size() {
    std::fill(header_data, header_data + sizeof(header_data), 0);
}

DHCPv6::DHCPv6(const uint8_t *buffer, uint32_t total_sz) 
: options_size() 
{
    if(total_sz == 0) 
        throw malformed_packet();
    // Relay Agent/Server Messages
    bool is_relay_msg = (buffer[0] == 12 || buffer[0] == 13);
    uint32_t required_size = is_relay_msg ? 2 : 4;
    if(total_sz < required_size)
        throw malformed_packet();
    std::copy(buffer, buffer + required_size, header_data);
    buffer += required_size;
    total_sz -= required_size;
    if(is_relay_message()) {
        if(total_sz < ipaddress_type::address_size * 2)
            throw malformed_packet();
        link_addr = buffer;
        peer_addr = buffer + ipaddress_type::address_size;
        buffer += ipaddress_type::address_size * 2;
        total_sz -= ipaddress_type::address_size * 2;
    }
    options_size = total_sz;
    while(total_sz) {
        if(total_sz < sizeof(uint16_t) * 2) 
            throw malformed_packet();
        
        uint16_t opt;
        std::memcpy(&opt, buffer, sizeof(uint16_t));
        opt = Endian::be_to_host(opt);
        uint16_t data_size;
        std::memcpy(&data_size, buffer + sizeof(uint16_t), sizeof(uint16_t));
        data_size = Endian::be_to_host(data_size);
        if(total_sz - sizeof(uint16_t) * 2 < data_size)
            throw malformed_packet();
        buffer += sizeof(uint16_t) * 2;
        add_option(
            option(opt, buffer, buffer + data_size)
        );
        buffer += data_size;
        total_sz -= sizeof(uint16_t) * 2 + data_size;
    }
}
    
void DHCPv6::add_option(const option &opt) {
    options_.push_back(opt);
}

const DHCPv6::option *DHCPv6::search_option(OptionTypes id) const {
    for(options_type::const_iterator it = options_.begin(); it != options_.end(); ++it) {
        if(it->option() == static_cast<uint16_t>(id))
            return &*it;
    }
    return 0;
}

uint8_t* DHCPv6::write_option(const option &opt, uint8_t* buffer) const {
    uint16_t uint16_t_buffer = Endian::host_to_be(opt.option());
    std::memcpy(buffer, &uint16_t_buffer, sizeof(uint16_t));
    uint16_t_buffer = Endian::host_to_be<uint16_t>(opt.length_field());
    std::memcpy(&buffer[sizeof(uint16_t)], &uint16_t_buffer, sizeof(uint16_t));
    return std::copy(
        opt.data_ptr(), 
        opt.data_ptr() + opt.data_size(), 
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

bool DHCPv6::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(!is_relay_message()) {
        if(total_sz < 4 || (ptr[0] == 12 || ptr[0] == 13))
            return false;
        return std::equal(header_data + 1, header_data + 4, ptr + 1);
    }
    return false;
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
    return search_and_convert<ia_na_type>(IA_NA);
}

DHCPv6::ia_ta_type DHCPv6::ia_ta() const {
    return search_and_convert<ia_ta_type>(IA_TA);
}

DHCPv6::ia_address_type DHCPv6::ia_address() const {
    return search_and_convert<ia_address_type>(IA_ADDR);
}

DHCPv6::option_request_type DHCPv6::option_request() const {
    return search_and_convert<option_request_type>(OPTION_REQUEST);
}

uint8_t DHCPv6::preference() const {
    return search_and_convert<uint8_t>(PREFERENCE);
}

uint16_t DHCPv6::elapsed_time() const {
    return search_and_convert<uint16_t>(ELAPSED_TIME);
}

DHCPv6::relay_msg_type DHCPv6::relay_message() const {
    return search_and_convert<relay_msg_type>(RELAY_MSG);
}

DHCPv6::authentication_type DHCPv6::authentication() const {
    return search_and_convert<authentication_type>(AUTH);
}

DHCPv6::ipaddress_type DHCPv6::server_unicast() const {
    return search_and_convert<ipaddress_type>(UNICAST);
}

DHCPv6::status_code_type DHCPv6::status_code() const {
    return search_and_convert<status_code_type>(STATUS_CODE);
}

bool DHCPv6::has_rapid_commit() const {
    return search_option(RAPID_COMMIT);
}

DHCPv6::user_class_type DHCPv6::user_class() const {
    return search_and_convert<user_class_type>(USER_CLASS);
}

DHCPv6::vendor_class_type DHCPv6::vendor_class() const {
    return search_and_convert<vendor_class_type>(VENDOR_CLASS);
}

DHCPv6::vendor_info_type DHCPv6::vendor_info() const {
    return search_and_convert<vendor_info_type>(VENDOR_OPTS);
}

DHCPv6::interface_id_type DHCPv6::interface_id() const {
    return search_and_convert<interface_id_type>(INTERFACE_ID);
}

uint8_t DHCPv6::reconfigure_msg() const {
    return search_and_convert<uint8_t>(RECONF_MSG);
}

bool DHCPv6::has_reconfigure_accept() const {
    return search_option(RECONF_ACCEPT);
}

DHCPv6::duid_type DHCPv6::client_id() const {
    return search_and_convert<duid_type>(CLIENTID);
}

DHCPv6::duid_type DHCPv6::server_id() const {
    return search_and_convert<duid_type>(SERVERID);
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
        option(IA_NA, buffer.begin(), buffer.end())
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
        option(IA_TA, buffer.begin(), buffer.end())
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
        option(IA_ADDR, buffer.begin(), buffer.end())
    );
}

void DHCPv6::option_request(const option_request_type &value) {
    typedef option_request_type::const_iterator iterator;
    
    std::vector<uint8_t> buffer(value.size() * sizeof(uint16_t));
    size_t index = 0;
    uint16_t uint16_t_buffer;
    for(iterator it = value.begin(); it != value.end(); ++it, index += 2) {
        uint16_t_buffer = Endian::host_to_be<uint16_t>(*it);
        std::memcpy(&buffer[index], &uint16_t_buffer, sizeof(uint16_t));
    }
    add_option(
        option(OPTION_REQUEST, buffer.begin(), buffer.end())
    );
}

void DHCPv6::preference(uint8_t value) {
    add_option(
        option(PREFERENCE, 1, &value)
    );
}

void DHCPv6::elapsed_time(uint16_t value) {
    value = Endian::host_to_be(value);
    add_option(
        option(ELAPSED_TIME, 2, (const uint8_t*)&value)
    );
}

void DHCPv6::relay_message(const relay_msg_type &value) {
    add_option(
        option(RELAY_MSG, value.begin(), value.end())
    );
}

void DHCPv6::authentication(const authentication_type &value) {
    std::vector<uint8_t> buffer(
        sizeof(uint8_t) * 3 + sizeof(uint64_t) + value.auth_info.size()
    );
    buffer[0] = value.protocol;
    buffer[1] = value.algorithm;
    buffer[2] = value.rdm;
    uint64_t uint64_t_buffer = Endian::host_to_be(value.replay_detection);
    std::memcpy(&buffer[3], &uint64_t_buffer, sizeof(uint64_t));
    std::copy(
        value.auth_info.begin(), 
        value.auth_info.end(),
        buffer.begin() + sizeof(uint8_t) * 3 + sizeof(uint64_t)
    );
    add_option(
        option(AUTH, buffer.begin(), buffer.end())
    );
}

void DHCPv6::server_unicast(const ipaddress_type &value) {
    add_option(
        option(UNICAST, value.begin(), value.end())
    );
}

void DHCPv6::status_code(const status_code_type &value) {
    std::vector<uint8_t> buffer(sizeof(uint16_t) + value.message.size());
    uint16_t uint16_t_buffer = Endian::host_to_be(value.code);
    std::memcpy(&buffer[0], &uint16_t_buffer, sizeof(uint16_t));
    std::copy(
        value.message.begin(), 
        value.message.end(), 
        buffer.begin() + sizeof(uint16_t)
    );
    add_option(
        option(STATUS_CODE, buffer.begin(), buffer.end())
    );
}

void DHCPv6::rapid_commit() {
    add_option(
        RAPID_COMMIT
    );
}

void DHCPv6::user_class(const user_class_type &value) {
    std::vector<uint8_t> buffer;
    Internals::class_option_data2option(value.data.begin(), value.data.end(), buffer);
    add_option(
        option(USER_CLASS, buffer.begin(), buffer.end())
    );
}

void DHCPv6::vendor_class(const vendor_class_type &value) {
    std::vector<uint8_t> buffer(
        sizeof(uint32_t)
    );
    uint32_t enterprise_number = Endian::host_to_be(value.enterprise_number);
    std::memcpy(&buffer[0], &enterprise_number, sizeof(uint32_t));
    Internals::class_option_data2option(
        value.vendor_class_data.begin(),
        value.vendor_class_data.end(),
        buffer,
        sizeof(uint32_t)
    );
    add_option(
        option(VENDOR_CLASS, buffer.begin(), buffer.end())
    );
}

void DHCPv6::vendor_info(const vendor_info_type &value) {
    std::vector<uint8_t> buffer(sizeof(uint32_t) + value.data.size());
    uint32_t enterprise_number = Endian::host_to_be(value.enterprise_number);
    std::memcpy(&buffer[0], &enterprise_number, sizeof(uint32_t));
    std::copy(
        value.data.begin(),
        value.data.end(),
        buffer.begin() + sizeof(uint32_t)
    );
    add_option(
        option(VENDOR_OPTS, buffer.begin(), buffer.end())
    );
}

void DHCPv6::interface_id(const interface_id_type &value) {
    add_option(
        option(INTERFACE_ID, value.begin(), value.end())
    );
}

void DHCPv6::reconfigure_msg(uint8_t value) {
    add_option(
        option(RECONF_MSG, 1, &value)
    );
}

void DHCPv6::reconfigure_accept() {
    add_option(RECONF_ACCEPT);
}


// DUIDs

DHCPv6::duid_llt DHCPv6::duid_llt::from_bytes(const uint8_t *buffer, uint32_t total_sz) 
{
    // at least one byte for lladdress
    if(total_sz < sizeof(uint16_t) + sizeof(uint32_t) + 1)
        throw std::runtime_error("Not enough size for a DUID_LLT identifier");
    duid_llt output;
    std::memcpy(&output.hw_type, buffer, sizeof(uint16_t));
    output.hw_type = Endian::be_to_host(output.hw_type);
    buffer += sizeof(uint16_t);
    std::memcpy(&output.time, buffer, sizeof(uint32_t));
    output.time = Endian::be_to_host(output.time);
    buffer += sizeof(uint32_t);
    total_sz -= sizeof(uint16_t) + sizeof(uint32_t);
    output.lladdress.assign(buffer, buffer + total_sz);
    return output;
}

PDU::serialization_type DHCPv6::duid_llt::serialize() const {
    serialization_type output(sizeof(uint16_t) + sizeof(uint32_t) + lladdress.size());
    uint16_t tmp_hw_type = Endian::host_to_be(hw_type);
    uint32_t tmp_time = Endian::host_to_be(time);
    std::memcpy(&output[0], &tmp_hw_type, sizeof(uint16_t));
    std::memcpy(&output[sizeof(uint16_t)], &tmp_time, sizeof(uint32_t));
    std::copy(
        lladdress.begin(),
        lladdress.end(),
        output.begin() + sizeof(uint16_t) + sizeof(uint32_t)
    );
    return output;
}

DHCPv6::duid_en DHCPv6::duid_en::from_bytes(const uint8_t *buffer, uint32_t total_sz) 
{
    // at least one byte for identifier
    if(total_sz < sizeof(uint32_t) + 1)
        throw std::runtime_error("Not enough size for a DUID_en identifier");
    duid_en output;
    std::memcpy(&output.enterprise_number, buffer, sizeof(uint32_t));
    output.enterprise_number = Endian::be_to_host(output.enterprise_number);
    buffer += sizeof(uint32_t);
    total_sz -= sizeof(uint32_t);
    output.identifier.assign(buffer, buffer + total_sz);
    return output;
}

PDU::serialization_type DHCPv6::duid_en::serialize() const {
    serialization_type output(sizeof(uint32_t) + identifier.size());
    uint32_t tmp_enterprise_number = Endian::host_to_be(enterprise_number);
    std::memcpy(&output[0], &tmp_enterprise_number, sizeof(uint32_t));
    std::copy(
        identifier.begin(),
        identifier.end(),
        output.begin() + sizeof(uint32_t)
    );
    return output;
}

DHCPv6::duid_ll DHCPv6::duid_ll::from_bytes(const uint8_t *buffer, uint32_t total_sz) 
{
    // at least one byte for lladdress
    if(total_sz < sizeof(uint16_t) + 1)
        throw std::runtime_error("Not enough size for a DUID_en identifier");
    duid_ll output;
    std::memcpy(&output.hw_type, buffer, sizeof(uint16_t));
    output.hw_type = Endian::be_to_host(output.hw_type);
    buffer += sizeof(uint16_t);
    total_sz -= sizeof(uint16_t);
    output.lladdress.assign(buffer, buffer + total_sz);
    return output;
}

PDU::serialization_type DHCPv6::duid_ll::serialize() const {
    serialization_type output(sizeof(uint16_t) + lladdress.size());
    uint16_t tmp_hw_type = Endian::host_to_be(hw_type);
    std::memcpy(&output[0], &tmp_hw_type, sizeof(uint16_t));
    std::copy(
        lladdress.begin(),
        lladdress.end(),
        output.begin() + sizeof(uint16_t)
    );
    return output;
}

void DHCPv6::client_id(const duid_type &value) {
    serialization_type buffer(sizeof(uint16_t) + value.data.size());
    uint16_t tmp_id = Endian::host_to_be(value.id);
    std::memcpy(&buffer[0], &tmp_id, sizeof(uint16_t));
    std::copy(
        value.data.begin(),
        value.data.end(),
        buffer.begin() + sizeof(uint16_t)
    );
    add_option(
        option(CLIENTID, buffer.begin(), buffer.end())
    );
}

void DHCPv6::server_id(const duid_type &value) {
    serialization_type buffer(sizeof(uint16_t) + value.data.size());
    uint16_t tmp_id = Endian::host_to_be(value.id);
    std::memcpy(&buffer[0], &tmp_id, sizeof(uint16_t));
    std::copy(
        value.data.begin(),
        value.data.end(),
        buffer.begin() + sizeof(uint16_t)
    );
    add_option(
        option(SERVERID, buffer.begin(), buffer.end())
    );
}

// Options

DHCPv6::ia_na_type DHCPv6::ia_na_type::from_option(const option &opt)
{
    if(opt.data_size() < sizeof(uint32_t) * 3)
        throw malformed_option();
    const uint8_t *ptr = opt.data_ptr() + sizeof(uint32_t) * 3;
    const uint32_t *ptr_32 = (const uint32_t*)opt.data_ptr();
    DHCPv6::ia_na_type output;
    output.id = Endian::be_to_host(*ptr_32++);
    output.t1 = Endian::be_to_host(*ptr_32++);
    output.t2 = Endian::be_to_host(*ptr_32++);
    output.options.assign(ptr, opt.data_ptr() + opt.data_size());
    return output;
}

DHCPv6::ia_ta_type DHCPv6::ia_ta_type::from_option(const option &opt)
{
    if(opt.data_size() < sizeof(uint32_t))
        throw malformed_option();
    const uint8_t *ptr = opt.data_ptr() + sizeof(uint32_t);
    const uint32_t *ptr_32 = (const uint32_t*)opt.data_ptr();
    DHCPv6::ia_ta_type output;
    output.id = Endian::be_to_host(*ptr_32++);
    output.options.assign(ptr, opt.data_ptr() + opt.data_size());
    return output;
}

DHCPv6::ia_address_type DHCPv6::ia_address_type::from_option(const option &opt)
{
    if(opt.data_size() < sizeof(uint32_t) * 2 + DHCPv6::ipaddress_type::address_size)
        throw malformed_option();
    const uint8_t *ptr = opt.data_ptr() + sizeof(uint32_t) * 2 + ipaddress_type::address_size;
    const uint32_t *ptr_32 = (const uint32_t*)(opt.data_ptr() + ipaddress_type::address_size);
    DHCPv6::ia_address_type output;
    output.address = opt.data_ptr();
    output.preferred_lifetime = Endian::be_to_host(*ptr_32++);
    output.valid_lifetime = Endian::be_to_host(*ptr_32++);
    output.options.assign(ptr, opt.data_ptr() + opt.data_size());
    return output;
}

DHCPv6::authentication_type DHCPv6::authentication_type::from_option(const option &opt)
{
    if(opt.data_size() < sizeof(uint8_t) * 3 + sizeof(uint64_t))
        throw malformed_option();
    const uint8_t *ptr = opt.data_ptr();
    authentication_type output;
    output.protocol = *ptr++;
    output.algorithm = *ptr++;
    output.rdm = *ptr++;
    std::memcpy(&output.replay_detection, ptr, sizeof(uint64_t));
    output.replay_detection = Endian::be_to_host(output.replay_detection);
    ptr += sizeof(uint64_t);
    output.auth_info.assign(ptr, opt.data_ptr() + opt.data_size());
    return output;
}

DHCPv6::status_code_type DHCPv6::status_code_type::from_option(const option &opt)
{
    if(opt.data_size() < sizeof(uint16_t))
        throw malformed_option();
    status_code_type output;
    std::memcpy(&output.code, opt.data_ptr(), sizeof(uint16_t));
    output.code = Endian::be_to_host(output.code);
    output.message.assign(
        opt.data_ptr() + sizeof(uint16_t),
        opt.data_ptr() + opt.data_size()
    );
    return output;
}

DHCPv6::vendor_info_type DHCPv6::vendor_info_type::from_option(const option &opt)
{
    if(opt.data_size() < sizeof(uint32_t))
        throw malformed_option();
    vendor_info_type output;
    std::memcpy(&output.enterprise_number, opt.data_ptr(), sizeof(uint32_t));
    output.enterprise_number = Endian::be_to_host(output.enterprise_number);
    output.data.assign(
        opt.data_ptr() + sizeof(uint32_t),
        opt.data_ptr() + opt.data_size()
    );
    return output;
}

DHCPv6::vendor_class_type DHCPv6::vendor_class_type::from_option(const option &opt)
{
    if(opt.data_size() < sizeof(uint32_t))
        throw malformed_option();
    typedef vendor_class_type::class_data_type data_type;
    vendor_class_type output;
    std::memcpy(&output.enterprise_number, opt.data_ptr(), sizeof(uint32_t));
    output.enterprise_number = Endian::be_to_host(output.enterprise_number);
    output.vendor_class_data = Internals::option2class_option_data<data_type>(
        opt.data_ptr() + sizeof(uint32_t),
        opt.data_size() - sizeof(uint32_t)
    );
    
    return output;
}

DHCPv6::duid_type DHCPv6::duid_type::from_option(const option &opt)
{
    if(opt.data_size() < sizeof(uint16_t) + 1)
        throw malformed_option();

    uint16_t uint16_t_buffer;
    std::memcpy(&uint16_t_buffer, opt.data_ptr(), sizeof(uint16_t));
    return duid_type(
        Endian::be_to_host(uint16_t_buffer),
        serialization_type(
            opt.data_ptr() + sizeof(uint16_t),
            opt.data_ptr() + opt.data_size()
        )
    );
}

DHCPv6::user_class_type DHCPv6::user_class_type::from_option(const option &opt)
{
    if(opt.data_size() < sizeof(uint16_t))
        throw malformed_option();
    user_class_type output;
    output.data = Internals::option2class_option_data<data_type>(
        opt.data_ptr(), opt.data_size()
    );
    return output;
}
} // namespace Tins
