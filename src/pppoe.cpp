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

#ifdef TINS_DEBUG
    #include <cassert>
#endif
#include <cstring>
#include "pppoe.h"
#include "exceptions.h"

namespace Tins {

PPPoE::PPPoE() 
: _header(), _tags_size()
{
    version(1);
    type(1);
}

PPPoE::PPPoE(const uint8_t *buffer, uint32_t total_sz) 
: _tags_size()
{
    if(total_sz < sizeof(_header))
        throw malformed_packet();
    std::memcpy(&_header, buffer, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    total_sz = std::min(total_sz, (uint32_t)payload_length());
    const uint8_t *end = buffer + total_sz;
    while(buffer < end) {
        if(buffer + sizeof(uint32_t) * 2 > end)
            throw malformed_packet();
        uint16_t opt_type;
        std::memcpy(&opt_type, buffer, sizeof(uint16_t));
        uint16_t opt_len;
        std::memcpy(&opt_len, buffer + sizeof(uint16_t), sizeof(uint16_t));
        buffer += sizeof(uint16_t) * 2;
        total_sz -= sizeof(uint16_t) * 2;
        if(Endian::be_to_host(opt_len) > total_sz)
            throw malformed_packet();
        add_tag(
            tag(
                static_cast<TagTypes>(opt_type), 
                Endian::be_to_host(opt_len), 
                buffer
            )
        );
        buffer += Endian::be_to_host(opt_len);
        total_sz -= Endian::be_to_host(opt_len);
    }
}

const PPPoE::tag *PPPoE::search_tag(TagTypes identifier) const {
    for(tags_type::const_iterator it = _tags.begin(); it != _tags.end(); ++it) {
        if(it->option() == identifier)
            return &*it;
    }
    return 0;
}

void PPPoE::version(small_uint<4> new_version) {
    _header.version = new_version;
}

void PPPoE::type(small_uint<4> new_type) {
    _header.type = new_type;
}

void PPPoE::code(uint8_t new_code) {
    _header.code = new_code;
}

void PPPoE::session_id(uint16_t new_session_id) {
    _header.session_id = Endian::host_to_be(new_session_id);
}

void PPPoE::payload_length(uint16_t new_payload_length) {
    _header.payload_length = Endian::host_to_be(new_payload_length);
}

uint32_t PPPoE::header_size() const {
    return sizeof(_header) + _tags_size;
}

void PPPoE::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) 
{
    #ifdef TINS_DEBUG
        assert(total_sz == sizeof(_header) + _tags_size);
    #endif
    std::memcpy(buffer, &_header, sizeof(_header));
    if(_tags_size > 0)
        ((pppoe_hdr*)buffer)->payload_length = Endian::host_to_be(_tags_size);
    buffer += sizeof(_header);
    uint16_t uint16_t_buffer;
    for(tags_type::const_iterator it = _tags.begin(); it != _tags.end(); ++it) {
        uint16_t_buffer = it->option();
        std::memcpy(buffer, &uint16_t_buffer, sizeof(uint16_t));
        uint16_t_buffer = Endian::host_to_be<uint16_t>(it->length_field());
        std::memcpy(buffer + sizeof(uint16_t), &uint16_t_buffer, sizeof(uint16_t));
        std::copy(
            it->data_ptr(), 
            it->data_ptr() + it->data_size(),
            buffer + sizeof(uint16_t) * 2
        );
        buffer += sizeof(uint16_t) * 2 + it->data_size();
    }
}

void PPPoE::add_tag(const tag &option) {
    _tags_size += option.data_size() + sizeof(uint16_t) * 2;
    _tags.push_back(option);
}

// *********************** Setters *************************

void PPPoE::end_of_list() {
    add_tag(
        END_OF_LIST
    );
}

void PPPoE::service_name(const std::string &value) {
    add_tag_iterable(SERVICE_NAME, value);
}

void PPPoE::ac_name(const std::string &value) {
    add_tag_iterable(AC_NAME, value);
}

void PPPoE::host_uniq(const byte_array &value) {
    add_tag_iterable(HOST_UNIQ, value);
}

void PPPoE::ac_cookie(const byte_array &value) {
    add_tag_iterable(AC_COOKIE, value);
}

void PPPoE::vendor_specific(const vendor_spec_type &value) {
    std::vector<uint8_t> buffer(sizeof(uint32_t) + value.data.size());
    uint32_t tmp_vendor_id = Endian::host_to_be(value.vendor_id);
    std::memcpy(&buffer[0], &tmp_vendor_id, sizeof(uint32_t));
    std::copy(
        value.data.begin(), 
        value.data.end(), 
        buffer.begin() + sizeof(uint32_t)
    );
    add_tag(
        tag(
            VENDOR_SPECIFIC,
            buffer.begin(),
            buffer.end()
        )
    );
}

void PPPoE::relay_session_id(const byte_array &value) {
    add_tag_iterable(RELAY_SESSION_ID, value);
}

void PPPoE::service_name_error(const std::string &value) {
    add_tag_iterable(SERVICE_NAME_ERROR, value);
}

void PPPoE::ac_system_error(const std::string &value) {
    add_tag_iterable(AC_SYSTEM_ERROR, value);
}

void PPPoE::generic_error(const std::string &value) {
    add_tag_iterable(GENERIC_ERROR, value);
}

// *********************** Getters *************************

std::string PPPoE::service_name() const {
    return search_and_convert<std::string>(SERVICE_NAME);
}

std::string PPPoE::ac_name() const {
    return search_and_convert<std::string>(AC_NAME);
}

byte_array PPPoE::host_uniq() const {
    return search_and_convert<byte_array>(HOST_UNIQ);
}

byte_array PPPoE::ac_cookie() const {
    return search_and_convert<byte_array>(AC_COOKIE);
}

PPPoE::vendor_spec_type PPPoE::vendor_specific() const {
    const tag *t = search_tag(VENDOR_SPECIFIC);
    if(!t)
        throw option_not_found();
    return t->to<vendor_spec_type>();
}

byte_array PPPoE::relay_session_id() const {
    return search_and_convert<byte_array>(RELAY_SESSION_ID);
}

std::string PPPoE::service_name_error() const {
    return search_and_convert<std::string>(SERVICE_NAME_ERROR);
}

std::string PPPoE::ac_system_error() const {
    return search_and_convert<std::string>(AC_SYSTEM_ERROR);
}

std::string PPPoE::generic_error() const {
    return search_and_convert<std::string>(GENERIC_ERROR);
}

PPPoE::vendor_spec_type PPPoE::vendor_spec_type::from_option(const tag &opt) {
    if(opt.data_size() < sizeof(uint32_t))
        throw malformed_option();
    vendor_spec_type output;
    std::memcpy(&output.vendor_id, opt.data_ptr(), sizeof(uint32_t));
    output.vendor_id = Endian::be_to_host(output.vendor_id);
    output.data.assign(
        opt.data_ptr() + sizeof(uint32_t), 
        opt.data_ptr() + opt.data_size()
    );
    return output;
}
} //namespace Tins

