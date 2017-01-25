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
#ifndef _WIN32
    #include <netinet/in.h>
#endif
#include "rawpdu.h"
#include "utils.h"
#include "exceptions.h"
#include "icmp.h"
#include "memory_helpers.h"

using std::memset;
using std::max;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PDU::metadata ICMP::extract_metadata(const uint8_t* /*buffer*/, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(icmp_header))) {
        throw malformed_packet();
    }
    return metadata(sizeof(icmp_header), pdu_flag, PDU::UNKNOWN);
}

ICMP::ICMP(Flags flag) 
: orig_timestamp_or_address_mask_(), recv_timestamp_(), trans_timestamp_() {
    memset(&header_, 0, sizeof(icmp_header));
    type(flag);
}

ICMP::ICMP(const uint8_t* buffer, uint32_t total_sz) 
: orig_timestamp_or_address_mask_(), recv_timestamp_(), trans_timestamp_() {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    if (type() == TIMESTAMP_REQUEST || type() == TIMESTAMP_REPLY) {
        original_timestamp(stream.read<uint32_t>());
        receive_timestamp(stream.read<uint32_t>());
        transmit_timestamp(stream.read<uint32_t>());
    }
    else if (type() == ADDRESS_MASK_REQUEST || type() == ADDRESS_MASK_REPLY) {
        address_mask(address_type(stream.read<uint32_t>()));
    }
    // Attempt to parse ICMP extensions
    try_parse_extensions(stream);
    if (stream) {
        inner_pdu(new RawPDU(stream.pointer(), stream.size()));
    }
}

void ICMP::code(uint8_t new_code) {
    header_.code = new_code;
}

void ICMP::type(Flags new_type) {
    header_.type = new_type;
}

void ICMP::checksum(uint16_t new_check) {
    header_.check = Endian::host_to_be(new_check);
}

void ICMP::id(uint16_t new_id) {
    header_.un.echo.id = Endian::host_to_be(new_id);
}

void ICMP::sequence(uint16_t new_seq) {
    header_.un.echo.sequence = Endian::host_to_be(new_seq);
}

void ICMP::gateway(address_type new_gw) {
    header_.un.gateway = Endian::host_to_be(static_cast<uint32_t>(new_gw));
}

void ICMP::mtu(uint16_t new_mtu) {
    header_.un.frag.mtu = Endian::host_to_be(new_mtu);
}

void ICMP::pointer(uint8_t new_pointer) {
    header_.un.rfc4884.pointer = new_pointer;
}

void ICMP::original_timestamp(uint32_t new_timestamp) {
    orig_timestamp_or_address_mask_ = Endian::host_to_be(new_timestamp);
}

void ICMP::receive_timestamp(uint32_t new_timestamp) {
    recv_timestamp_ = Endian::host_to_be(new_timestamp);
}

void ICMP::transmit_timestamp(uint32_t new_timestamp) {
    trans_timestamp_ = Endian::host_to_be(new_timestamp);
}

void ICMP::address_mask(address_type new_mask) {
    orig_timestamp_or_address_mask_ = Endian::host_to_be(static_cast<uint32_t>(new_mask));
}

uint32_t ICMP::header_size() const {
    uint32_t extra = 0;
    if (type() == TIMESTAMP_REQUEST || type() == TIMESTAMP_REPLY) {
        extra = sizeof(uint32_t) * 3;
    }
    else if (type() == ADDRESS_MASK_REQUEST || type() == ADDRESS_MASK_REPLY)  {
        extra = sizeof(uint32_t);
    }

    return sizeof(icmp_header) + extra;
}

uint32_t ICMP::trailer_size() const {
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

void ICMP::set_echo_request(uint16_t id, uint16_t seq) {
    type(ECHO_REQUEST);
    this->id(id);
    sequence(seq);
}

void ICMP::set_echo_reply(uint16_t id, uint16_t seq) {
    type(ECHO_REPLY);
    this->id(id);
    sequence(seq);
}

void ICMP::set_info_request(uint16_t id, uint16_t seq) {
    type(INFO_REQUEST);
    code(0);
    this->id(id);
    sequence(seq);
}

void ICMP::set_info_reply(uint16_t id, uint16_t seq) {
    type(INFO_REPLY);
    code(0);
    this->id(id);
    sequence(seq);
}

void ICMP::set_dest_unreachable() {
    type(DEST_UNREACHABLE);
}

void ICMP::set_time_exceeded(bool ttl_exceeded) {
    type(TIME_EXCEEDED);
    code((ttl_exceeded) ? 0 : 1);
}

void ICMP::set_param_problem(bool set_pointer, uint8_t bad_octet) {
    type(PARAM_PROBLEM);
    if (set_pointer) {
        code(0);
        pointer(bad_octet);
    }
    else {
        code(1);
    }
}

void ICMP::set_source_quench() {
    type(SOURCE_QUENCH);
}

void ICMP::set_redirect(uint8_t icode, address_type address) {
    type(REDIRECT);
    code(icode);
    gateway(address);
}

void ICMP::use_length_field(bool value) {
    // We just need a non 0 value here, we'll use the right value on 
    // write_serialization
    header_.un.rfc4884.length = value ? 1 : 0;
}

void ICMP::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    OutputMemoryStream stream(buffer, total_sz);

    // If extensions are allowed and we have to set the length field
    if (are_extensions_allowed()) {
        uint32_t length_value = get_adjusted_inner_pdu_size();
        // If the next pdu size is greater than 128, we are forced to set the length field
        if (length() != 0 || length_value > 128) {
            if (length_value) {
                // If we have extensions, we'll have at least 128 bytes.
                // Otherwise, just use the length 
                length_value = has_extensions() ? max(length_value, 128U) 
                                                : length_value;
            }
            else {
                length_value = 0;
            }
            // This field uses 32 bit words as the unit
            header_.un.rfc4884.length = length_value / sizeof(uint32_t);
        }
    }

    // Write the header using checksum 0
    header_.check = 0;
    stream.write(header_);

    if (type() == TIMESTAMP_REQUEST || type() == TIMESTAMP_REPLY) {
        stream.write(original_timestamp());
        stream.write(receive_timestamp());
        stream.write(transmit_timestamp());
    }
    else if (type() == ADDRESS_MASK_REQUEST || type() == ADDRESS_MASK_REPLY) {
        stream.write(address_mask());
    }

    if (has_extensions()) {
        uint8_t* extensions_ptr = buffer + sizeof(icmp_header);
        if (inner_pdu()) {
            // Get the size of the next pdu, padded to the next 32 bit boundary
            uint32_t inner_pdu_size = get_adjusted_inner_pdu_size();
            // If it's lower than 128, we need to padd enough zeroes to make it 128 bytes long
            if (inner_pdu_size < 128) {
                memset(extensions_ptr + inner_pdu_size, 0, 128 - inner_pdu_size);
                inner_pdu_size = 128;
            }
            else {
                // If the packet has to be padded to 32 bits, append the amount 
                // of zeroes we need
                uint32_t diff = inner_pdu_size - inner_pdu()->size();
                memset(extensions_ptr + inner_pdu_size, 0, diff);
            }
            extensions_ptr += inner_pdu_size;
        }
        // Now serialize the exensions where they should be
        extensions_.serialize(extensions_ptr, total_sz - (extensions_ptr - buffer));
    }

    // Calculate checksum and write them on the serialized header
    header_.check = ~Utils::sum_range(buffer, buffer + total_sz);
    memcpy(buffer + 2, &header_.check, sizeof(uint16_t));
}

uint32_t ICMP::get_adjusted_inner_pdu_size() const {
    // This gets the size of the next pdu, padded to the next 32 bit word boundary
    return Internals::get_padded_icmp_inner_pdu_size(inner_pdu(), sizeof(uint32_t));
}

void ICMP::try_parse_extensions(InputMemoryStream& stream) {
    // Check if this is one of the types defined in RFC 4884
    if (are_extensions_allowed()) {
        Internals::try_parse_icmp_extensions(stream, length() * sizeof(uint32_t), 
            extensions_);
    }
}

bool ICMP::are_extensions_allowed() const {
    return type() == DEST_UNREACHABLE || type() == TIME_EXCEEDED || type() == PARAM_PROBLEM;
}

bool ICMP::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(icmp_header)) {
        return false;
    }
    const icmp_header* icmp_ptr = (const icmp_header*)ptr;
    if ((header_.type == ECHO_REQUEST && icmp_ptr->type == ECHO_REPLY) || 
        (header_.type == TIMESTAMP_REQUEST && icmp_ptr->type == TIMESTAMP_REPLY) ||
        (header_.type == ADDRESS_MASK_REQUEST && icmp_ptr->type == ADDRESS_MASK_REPLY)) {
        return icmp_ptr->un.echo.id == header_.un.echo.id && 
               icmp_ptr->un.echo.sequence == header_.un.echo.sequence;
    }
    return false;
}

} // namespace Tins
