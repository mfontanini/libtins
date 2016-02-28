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
#include "pppoe.h"
#include "rawpdu.h"
#include "exceptions.h"
#include "memory_helpers.h"

using std::string;
using std::vector;
using std::memcpy;
using std::copy;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PPPoE::PPPoE() 
: header_(), tags_size_() {
    version(1);
    type(1);
}

PPPoE::PPPoE(const uint8_t* buffer, uint32_t total_sz) 
: tags_size_() {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_); 
    stream.size(std::min(stream.size(), (size_t)payload_length()));
    // If this is a session data packet
    if (code() == 0) {
        if (stream) {
            inner_pdu(
                new RawPDU(stream.pointer(), stream.size())
            );
        }
    }
    else {
        while (stream) {
            TagTypes opt_type = static_cast<TagTypes>(stream.read<uint16_t>());
            uint16_t opt_len = stream.read_be<uint16_t>();
            if (!stream.can_read(opt_len)) {
                throw malformed_packet();
            }
            add_tag(tag(opt_type, opt_len, stream.pointer()));
            stream.skip(opt_len);
        }
    }
}

const PPPoE::tag* PPPoE::search_tag(TagTypes identifier) const {
    for (tags_type::const_iterator it = tags_.begin(); it != tags_.end(); ++it) {
        if (it->option() == identifier) {
            return &*it;
        }
    }
    return 0;
}

void PPPoE::version(small_uint<4> new_version) {
    header_.version = new_version;
}

void PPPoE::type(small_uint<4> new_type) {
    header_.type = new_type;
}

void PPPoE::code(uint8_t new_code) {
    header_.code = new_code;
}

void PPPoE::session_id(uint16_t new_session_id) {
    header_.session_id = Endian::host_to_be(new_session_id);
}

void PPPoE::payload_length(uint16_t new_payload_length) {
    header_.payload_length = Endian::host_to_be(new_payload_length);
}

uint32_t PPPoE::header_size() const {
    return sizeof(header_) + tags_size_;
}

void PPPoE::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    OutputMemoryStream stream(buffer, total_sz);
    if (tags_size_ > 0) {
        payload_length(tags_size_);
    }
    stream.write(header_);
    for (tags_type::const_iterator it = tags_.begin(); it != tags_.end(); ++it) {
        stream.write<uint16_t>(it->option());
        stream.write(Endian::host_to_be<uint16_t>(it->length_field()));
        stream.write(it->data_ptr(), it->data_size());
    }
}

void PPPoE::add_tag(const tag& option) {
    tags_size_ += static_cast<uint16_t>(option.data_size() + sizeof(uint16_t) * 2);
    tags_.push_back(option);
}

// *********************** Setters *************************

void PPPoE::end_of_list() {
    add_tag(
        END_OF_LIST
    );
}

void PPPoE::service_name(const string& value) {
    add_tag_iterable(SERVICE_NAME, value);
}

void PPPoE::ac_name(const string& value) {
    add_tag_iterable(AC_NAME, value);
}

void PPPoE::host_uniq(const byte_array& value) {
    add_tag_iterable(HOST_UNIQ, value);
}

void PPPoE::ac_cookie(const byte_array& value) {
    add_tag_iterable(AC_COOKIE, value);
}

void PPPoE::vendor_specific(const vendor_spec_type& value) {
    vector<uint8_t> buffer(sizeof(uint32_t) + value.data.size());
    uint32_t tmp_vendor_id = Endian::host_to_be(value.vendor_id);
    memcpy(&buffer[0], &tmp_vendor_id, sizeof(uint32_t));
    copy(
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

void PPPoE::relay_session_id(const byte_array& value) {
    add_tag_iterable(RELAY_SESSION_ID, value);
}

void PPPoE::service_name_error(const std::string& value) {
    add_tag_iterable(SERVICE_NAME_ERROR, value);
}

void PPPoE::ac_system_error(const std::string& value) {
    add_tag_iterable(AC_SYSTEM_ERROR, value);
}

void PPPoE::generic_error(const std::string& value) {
    add_tag_iterable(GENERIC_ERROR, value);
}

// *********************** Getters *************************

string PPPoE::service_name() const {
    return search_and_convert<std::string>(SERVICE_NAME);
}

string PPPoE::ac_name() const {
    return search_and_convert<std::string>(AC_NAME);
}

byte_array PPPoE::host_uniq() const {
    return search_and_convert<byte_array>(HOST_UNIQ);
}

byte_array PPPoE::ac_cookie() const {
    return search_and_convert<byte_array>(AC_COOKIE);
}

PPPoE::vendor_spec_type PPPoE::vendor_specific() const {
    const tag* t = search_tag(VENDOR_SPECIFIC);
    if (!t) {
        throw option_not_found();
    }
    return t->to<vendor_spec_type>();
}

byte_array PPPoE::relay_session_id() const {
    return search_and_convert<byte_array>(RELAY_SESSION_ID);
}

string PPPoE::service_name_error() const {
    return search_and_convert<string>(SERVICE_NAME_ERROR);
}

string PPPoE::ac_system_error() const {
    return search_and_convert<string>(AC_SYSTEM_ERROR);
}

string PPPoE::generic_error() const {
    return search_and_convert<string>(GENERIC_ERROR);
}

PPPoE::vendor_spec_type PPPoE::vendor_spec_type::from_option(const tag& opt) {
    if (opt.data_size() < sizeof(uint32_t)) {
        throw malformed_option();
    }
    vendor_spec_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.vendor_id = stream.read_be<uint32_t>();
    stream.read(output.data, stream.size());
    return output;
}

} //namespace Tins
