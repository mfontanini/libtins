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

#include <vector>
#include <algorithm>
#include "dhcpv6.h"
#include "exceptions.h"
#include "memory_helpers.h"

using std::find_if;
using std::copy;
using std::vector;
using std::runtime_error;
using std::memcpy;
using std::equal;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PDU::metadata DHCPv6::extract_metadata(const uint8_t* /*buffer*/, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < 2)) {
        throw malformed_packet();
    }
    return metadata(total_sz, pdu_flag, PDU::UNKNOWN);
}

DHCPv6::DHCPv6() 
: header_data_(), options_size_() {

}

DHCPv6::DHCPv6(const uint8_t* buffer, uint32_t total_sz) 
: options_size_() {
    InputMemoryStream stream(buffer, total_sz);
    if (!stream) {
        throw malformed_packet();
    }
    // Relay Agent/Server Messages
    const MessageType message_type = (MessageType)*stream.pointer();
    bool is_relay_msg = (message_type == RELAY_FORWARD || message_type == RELAY_REPLY);
    uint32_t required_size = is_relay_msg ? 2 : 4;
    stream.read(&header_data_, required_size);
    if (is_relay_message()) {
        stream.read(link_addr_);
        stream.read(peer_addr_);
    }
    while (stream) {
        uint16_t opt = stream.read_be<uint16_t>();
        uint16_t data_size = stream.read_be<uint16_t>();
        if (!stream.can_read(data_size)) {
            throw malformed_packet();
        }
        add_option(option(opt, stream.pointer(), stream.pointer() + data_size));
        stream.skip(data_size);
    }
}
    
void DHCPv6::add_option(const option& opt) {
    options_.push_back(opt);
    options_size_ += opt.data_size() + sizeof(uint16_t) * 2;
}

bool DHCPv6::remove_option(OptionTypes type) {
    options_type::iterator iter = search_option_iterator(type);
    if (iter == options_.end()) {
        return false;
    }
    options_size_ -= iter->data_size() + sizeof(uint16_t) * 2;
    options_.erase(iter);
    return true;
}

const DHCPv6::option* DHCPv6::search_option(OptionTypes type) const {
    // Search for the iterator. If we found something, return it, otherwise return nullptr.
    options_type::const_iterator iter = search_option_iterator(type);
    return (iter != options_.end()) ? &*iter : 0;
}

DHCPv6::options_type::const_iterator DHCPv6::search_option_iterator(OptionTypes type) const {
    Internals::option_type_equality_comparator<option> comparator(type);
    return find_if(options_.begin(), options_.end(), comparator);
}

DHCPv6::options_type::iterator DHCPv6::search_option_iterator(OptionTypes type) {
    Internals::option_type_equality_comparator<option> comparator(type);
    return find_if(options_.begin(), options_.end(), comparator);
}

void DHCPv6::write_option(const option& opt, OutputMemoryStream& stream) const {
    stream.write_be<uint16_t>(opt.option());
    stream.write_be<uint16_t>(opt.length_field());
    stream.write(opt.data_ptr(), opt.data_size());
}
    
void DHCPv6::msg_type(MessageType type) {
    header_data_[0] = static_cast<uint8_t>(type);
}

void DHCPv6::hop_count(uint8_t count) {
    header_data_[1] = count;
}

void DHCPv6::transaction_id(small_uint<24> id) {
    uint32_t id_32 = id;
    header_data_[1] = id_32 >> 16;
    header_data_[2] = id_32 >> 8;
    header_data_[3] = id_32 & 0xff;
}

void DHCPv6::peer_address(const ipaddress_type& addr) {
    peer_addr_ = addr;
}

void DHCPv6::link_address(const ipaddress_type& addr) {
    link_addr_ = addr;
}

bool DHCPv6::is_relay_message() const {
    return msg_type() == 12 || msg_type() == 13;
}

uint32_t DHCPv6::header_size() const {
    return (is_relay_message() ? (2 + ipaddress_type::address_size * 2) : 4) + options_size_;
}

bool DHCPv6::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (!is_relay_message()) {
        if (total_sz < 4 || (ptr[0] == 12 || ptr[0] == 13)) {
            return false;
        }
        return equal(header_data_ + 1, header_data_ + 4, ptr + 1);
    }
    return false;
}

void DHCPv6::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    const uint32_t required_size = is_relay_message() ? 2 : 4;
    OutputMemoryStream stream(buffer, total_sz);
    stream.write(header_data_, required_size);
    if (is_relay_message()) {
        stream.write(link_addr_);
        stream.write(peer_addr_);
    }
    for (options_type::const_iterator it = options_.begin(); it != options_.end(); ++it) {
        write_option(*it, stream);
    }
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
    return search_option(RAPID_COMMIT) != NULL;
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
    return search_option(RECONF_ACCEPT) != NULL;
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

void DHCPv6::ia_na(const ia_na_type& value) {
    vector<uint8_t> buffer(sizeof(uint32_t) * 3 + value.options.size());
    OutputMemoryStream stream(buffer);
    stream.write_be(value.id);
    stream.write_be(value.t1);
    stream.write_be(value.t2);
    stream.write(value.options.begin(), value.options.end());
    add_option(option(IA_NA, buffer.begin(), buffer.end()));
}

void DHCPv6::ia_ta(const ia_ta_type& value) {
    vector<uint8_t> buffer(sizeof(uint32_t) + value.options.size());
    OutputMemoryStream stream(buffer);
    stream.write_be(value.id);
    stream.write(value.options.begin(), value.options.end());
    add_option(option(IA_TA, buffer.begin(), buffer.end()));
}

void DHCPv6::ia_address(const ia_address_type& value) {
    vector<uint8_t> buffer(
        sizeof(uint32_t) * 2 + ipaddress_type::address_size + value.options.size()
    );
    OutputMemoryStream stream(buffer);
    stream.write(value.address);
    stream.write_be(value.preferred_lifetime);
    stream.write_be(value.valid_lifetime);
    stream.write(value.options.begin(), value.options.end());
    add_option(option(IA_ADDR, buffer.begin(), buffer.end()));
}

void DHCPv6::option_request(const option_request_type& value) {
    typedef option_request_type::const_iterator iterator;
    
    vector<uint8_t> buffer(value.size() * sizeof(uint16_t));
    OutputMemoryStream stream(buffer);
    for (iterator it = value.begin(); it != value.end(); ++it) {
        stream.write_be(*it);
    }
    add_option(option(OPTION_REQUEST, buffer.begin(), buffer.end()));
}

void DHCPv6::preference(uint8_t value) {
    add_option(option(PREFERENCE, 1, &value));
}

void DHCPv6::elapsed_time(uint16_t value) {
    value = Endian::host_to_be(value);
    add_option(option(ELAPSED_TIME, 2, (const uint8_t*)&value));
}

void DHCPv6::relay_message(const relay_msg_type& value) {
    add_option(option(RELAY_MSG, value.begin(), value.end()));
}

void DHCPv6::authentication(const authentication_type& value) {
    vector<uint8_t> buffer(
        sizeof(uint8_t) * 3 + sizeof(uint64_t) + value.auth_info.size()
    );
    OutputMemoryStream stream(buffer);
    stream.write(value.protocol);
    stream.write(value.algorithm);
    stream.write(value.rdm);
    stream.write_be(value.replay_detection);
    stream.write(value.auth_info.begin(), value.auth_info.end());
    add_option(option(AUTH, buffer.begin(), buffer.end()));
}

void DHCPv6::server_unicast(const ipaddress_type& value) {
    add_option(option(UNICAST, value.begin(), value.end()));
}

void DHCPv6::status_code(const status_code_type& value) {
    vector<uint8_t> buffer(sizeof(uint16_t) + value.message.size());
    OutputMemoryStream stream(buffer);
    stream.write_be(value.code);
    stream.write(value.message.begin(), value.message.end());
    add_option(option(STATUS_CODE, buffer.begin(), buffer.end()));
}

void DHCPv6::rapid_commit() {
    add_option(RAPID_COMMIT);
}

void DHCPv6::user_class(const user_class_type& value) {
    vector<uint8_t> buffer;
    Internals::class_option_data2option(value.data.begin(), value.data.end(), buffer);
    add_option(option(USER_CLASS, buffer.begin(), buffer.end()));
}

void DHCPv6::vendor_class(const vendor_class_type& value) {
    vector<uint8_t> buffer(sizeof(uint32_t));
    OutputMemoryStream stream(buffer);
    stream.write_be(value.enterprise_number);
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

void DHCPv6::vendor_info(const vendor_info_type& value) {
    vector<uint8_t> buffer(sizeof(uint32_t) + value.data.size());
    OutputMemoryStream stream(buffer);
    stream.write_be(value.enterprise_number);
    stream.write(value.data.begin(), value.data.end());
    add_option(option(VENDOR_OPTS, buffer.begin(), buffer.end()));
}

void DHCPv6::interface_id(const interface_id_type& value) {
    add_option(option(INTERFACE_ID, value.begin(), value.end()));
}

void DHCPv6::reconfigure_msg(uint8_t value) {
    add_option(option(RECONF_MSG, 1, &value));
}

void DHCPv6::reconfigure_accept() {
    add_option(RECONF_ACCEPT);
}

void DHCPv6::client_id(const duid_type& value) {
    serialization_type buffer(sizeof(uint16_t) + value.data.size());
    OutputMemoryStream stream(buffer);
    stream.write_be(value.id);
    stream.write(value.data.begin(), value.data.end());
    add_option(option(CLIENTID, buffer.begin(), buffer.end()));
}

void DHCPv6::server_id(const duid_type& value) {
    serialization_type buffer(sizeof(uint16_t) + value.data.size());
    OutputMemoryStream stream(buffer);
    stream.write_be(value.id);
    stream.write(value.data.begin(), value.data.end());
    add_option(option(SERVERID, buffer.begin(), buffer.end()));
}

// DUIDs

DHCPv6::duid_llt DHCPv6::duid_llt::from_bytes(const uint8_t* buffer, uint32_t total_sz) {
    // at least one byte for lladdress
    if (total_sz < sizeof(uint16_t) + sizeof(uint32_t) + 1) {
        throw runtime_error("Not enough size for a DUID_LLT identifier");
    }
    InputMemoryStream stream(buffer, total_sz);
    duid_llt output;
    output.hw_type = stream.read_be<uint16_t>();
    output.time = stream.read_be<uint32_t>();
    stream.read(output.lladdress, stream.size());
    return output;
}

PDU::serialization_type DHCPv6::duid_llt::serialize() const {
    serialization_type output(sizeof(uint16_t) + sizeof(uint32_t) + lladdress.size());
    OutputMemoryStream stream(output);
    stream.write_be(hw_type);
    stream.write_be(time);
    stream.write(lladdress.begin(), lladdress.end());
    return output;
}

DHCPv6::duid_en DHCPv6::duid_en::from_bytes(const uint8_t* buffer, uint32_t total_sz) {
    // at least one byte for identifier
    if (total_sz < sizeof(uint32_t) + 1) {
        throw runtime_error("Not enough size for a DUID_en identifier");
    }
    InputMemoryStream stream(buffer, total_sz);
    duid_en output;
    output.enterprise_number = stream.read_be<uint32_t>();
    stream.read(output.identifier, stream.size());
    return output;
}

PDU::serialization_type DHCPv6::duid_en::serialize() const {
    serialization_type output(sizeof(uint32_t) + identifier.size());
    OutputMemoryStream stream(output);
    stream.write_be(enterprise_number);
    stream.write(identifier.begin(), identifier.end());
    return output;
}

DHCPv6::duid_ll DHCPv6::duid_ll::from_bytes(const uint8_t* buffer, uint32_t total_sz) {
    // at least one byte for lladdress
    if (total_sz < sizeof(uint16_t) + 1) { 
        throw runtime_error("Not enough size for a DUID_en identifier");
    }
    InputMemoryStream stream(buffer, total_sz);
    duid_ll output;
    output.hw_type = stream.read_be<uint16_t>();
    stream.read(output.lladdress, stream.size());
    return output;
}

PDU::serialization_type DHCPv6::duid_ll::serialize() const {
    serialization_type output(sizeof(uint16_t) + lladdress.size());
    OutputMemoryStream stream(output);
    stream.write_be(hw_type);
    stream.write(lladdress.begin(), lladdress.end());
    return output;
}

// Options

DHCPv6::ia_na_type DHCPv6::ia_na_type::from_option(const option& opt) {
    if (opt.data_size() < sizeof(uint32_t) * 3) {
        throw malformed_option();
    }
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    DHCPv6::ia_na_type output;
    output.id = stream.read_be<uint32_t>();
    output.t1 = stream.read_be<uint32_t>();
    output.t2 = stream.read_be<uint32_t>();
    stream.read(output.options, stream.size());
    return output;
}

DHCPv6::ia_ta_type DHCPv6::ia_ta_type::from_option(const option& opt) {
    if (opt.data_size() < sizeof(uint32_t)) {
        throw malformed_option();
    }
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    DHCPv6::ia_ta_type output;
    output.id = stream.read_be<uint32_t>();
    stream.read(output.options, stream.size());
    return output;
}

DHCPv6::ia_address_type DHCPv6::ia_address_type::from_option(const option& opt) {
    if (opt.data_size() < sizeof(uint32_t) * 2 + DHCPv6::ipaddress_type::address_size) {
        throw malformed_option();
    }
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    DHCPv6::ia_address_type output;
    stream.read(output.address);
    output.preferred_lifetime = stream.read_be<uint32_t>();
    output.valid_lifetime = stream.read_be<uint32_t>();
    stream.read(output.options, stream.size());
    return output;
}

DHCPv6::authentication_type DHCPv6::authentication_type::from_option(const option& opt) {
    if (opt.data_size() < sizeof(uint8_t) * 3 + sizeof(uint64_t)) {
        throw malformed_option();
    }
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    authentication_type output;
    output.protocol = stream.read<uint8_t>();
    output.algorithm = stream.read<uint8_t>();
    output.rdm = stream.read<uint8_t>();
    output.replay_detection = stream.read_be<uint64_t>();
    stream.read(output.auth_info, stream.size());
    return output;
}

DHCPv6::status_code_type DHCPv6::status_code_type::from_option(const option& opt) {
    if (opt.data_size() < sizeof(uint16_t)) {
        throw malformed_option();
    }
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    status_code_type output;
    output.code = stream.read_be<uint16_t>();
    output.message.assign(stream.pointer(), stream.pointer() + stream.size());
    return output;
}

DHCPv6::vendor_info_type DHCPv6::vendor_info_type::from_option(const option& opt) {
    if (opt.data_size() < sizeof(uint32_t)) {
        throw malformed_option();
    }
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    vendor_info_type output;
    output.enterprise_number = stream.read_be<uint32_t>();
    stream.read(output.data, stream.size());
    return output;
}

DHCPv6::vendor_class_type DHCPv6::vendor_class_type::from_option(const option& opt) {
    if (opt.data_size() < sizeof(uint32_t)) {
        throw malformed_option();
    }
    typedef vendor_class_type::class_data_type data_type;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    vendor_class_type output;
    output.enterprise_number = stream.read_be<uint32_t>();
    output.vendor_class_data = Internals::option2class_option_data<data_type>(
        stream.pointer(),
        stream.size()
    );
    
    return output;
}

DHCPv6::duid_type DHCPv6::duid_type::from_option(const option& opt) {
    if (opt.data_size() < sizeof(uint16_t) + 1) {
        throw malformed_option();
    }
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    uint16_t id = stream.read_be<uint16_t>();
    return duid_type(
        id,
        serialization_type(stream.pointer(), stream.pointer() + stream.size())
    );
}

DHCPv6::user_class_type DHCPv6::user_class_type::from_option(const option& opt) {
    if (opt.data_size() < sizeof(uint16_t)) {
        throw malformed_option();
    }
    user_class_type output;
    output.data = Internals::option2class_option_data<data_type>(
        opt.data_ptr(), static_cast<uint32_t>(opt.data_size())
    );
    return output;
}

} // namespace Tins
