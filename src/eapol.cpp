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
#include <stdexcept>
#include <algorithm>
#include "eapol.h"
#include "rsn_information.h"
#include "exceptions.h"
#include "rawpdu.h"
#include "memory_helpers.h"

using std::copy;
using std::min;
using std::memset;
using std::memcpy;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PDU::metadata EAPOL::extract_metadata(const uint8_t *buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(eapol_header))) {
        throw malformed_packet();
    }
    const eapol_header* header = (const eapol_header*)buffer;
    uint32_t advertised_size = Endian::be_to_host<uint16_t>(header->length) + 4;
    return metadata(min(total_sz, advertised_size), pdu_flag, PDU::UNKNOWN);
}

EAPOL::EAPOL(uint8_t packet_type, EAPOLTYPE type) 
: header_() {
    header_.version = 1;
    header_.packet_type = packet_type;
    header_.type = (uint8_t)type;
}

EAPOL::EAPOL(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
}

EAPOL* EAPOL::from_bytes(const uint8_t* buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(eapol_header))) {
        throw malformed_packet();
    }
    const eapol_header* ptr = (const eapol_header*)buffer;
    uint32_t data_len = Endian::be_to_host<uint16_t>(ptr->length);
    // at least 4 for fields always present
    total_sz = min(
        total_sz, 
        data_len + 4
    );
    switch(ptr->type) {
        case RC4:
            return new Tins::RC4EAPOL(buffer, total_sz);
            break;
        case RSN:
        case EAPOL_WPA:
            return new Tins::RSNEAPOL(buffer, total_sz);
            break;
    }
    return 0;
}

void EAPOL::version(uint8_t new_version) {
    header_.version = new_version;
}
        
void EAPOL::packet_type(uint8_t new_ptype) {
    header_.packet_type = new_ptype;
}

void EAPOL::length(uint16_t new_length) {
    header_.length = Endian::host_to_be(new_length);
}

void EAPOL::type(uint8_t new_type) {
    header_.type = new_type;
}

void EAPOL::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    OutputMemoryStream stream(buffer, total_sz);
    length(total_sz - 4);
    stream.write(header_);
    memcpy(buffer, &header_, sizeof(header_));
    write_body(stream);
}

/* RC4EAPOL */

RC4EAPOL::RC4EAPOL() 
: EAPOL(0x03, RC4) {
    memset(&header_, 0, sizeof(header_));
}

RC4EAPOL::RC4EAPOL(const uint8_t* buffer, uint32_t total_sz) 
: EAPOL(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(sizeof(eapol_header));
    stream.read(header_);
    if (stream.size() >= key_length()) {
        stream.read(key_, key_length());
        if (stream) {
            inner_pdu(new RawPDU(stream.pointer(), stream.size()));
        }
    }
}

void RC4EAPOL::key_length(uint16_t length) {
    header_.key_length = Endian::host_to_be(length);
}
        
void RC4EAPOL::replay_counter(uint64_t value) {
    header_.replay_counter = Endian::host_to_be(value);
}

void RC4EAPOL::key_iv(const uint8_t* ptr) {
    copy(ptr, ptr + sizeof(header_.key_iv), header_.key_iv);
}

void RC4EAPOL::key_flag(small_uint<1> flag) {
    header_.key_flag = flag;
}

void RC4EAPOL::key_index(small_uint<7> new_key_index) {
    header_.key_index = new_key_index;
}

void RC4EAPOL::key_sign(const uint8_t* ptr) {
    memcpy(header_.key_sign, ptr, sizeof(header_.key_sign));
}

void RC4EAPOL::key(const key_type& new_key) {
    key_ = new_key;
}

uint32_t RC4EAPOL::header_size() const {
    return static_cast<uint32_t>(sizeof(eapol_header) + sizeof(header_) + key_.size());
}

void RC4EAPOL::write_body(OutputMemoryStream& stream) {
    if (key_.size()) {
        header_.key_length = Endian::host_to_be(static_cast<uint16_t>(key_.size()));
    }
    stream.write(header_);
    stream.write(key_.begin(), key_.end());
}

/* RSNEAPOL */


RSNEAPOL::RSNEAPOL() 
: EAPOL(0x03, RSN) {
    memset(&header_, 0, sizeof(header_));
}

RSNEAPOL::RSNEAPOL(const uint8_t* buffer, uint32_t total_sz) 
: EAPOL(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(sizeof(eapol_header));
    stream.read(header_);
    if (stream.size() >= wpa_length()) {
        stream.read(key_, wpa_length());
        if (stream) {
            inner_pdu(new RawPDU(stream.pointer(), stream.size()));
        }
    }
}

void RSNEAPOL::nonce(const uint8_t* ptr) {
    copy(ptr, ptr + nonce_size, header_.nonce);
}

void RSNEAPOL::rsc(const uint8_t* ptr) {
    copy(ptr, ptr + rsc_size, header_.rsc);
}

void RSNEAPOL::id(const uint8_t* ptr) {
    copy(ptr, ptr + id_size, header_.id);
}

void RSNEAPOL::replay_counter(uint64_t new_replay_counter) {
    header_.replay_counter = Endian::host_to_be(new_replay_counter);
}

void RSNEAPOL::mic(const uint8_t* ptr) {
    copy(ptr, ptr + mic_size, header_.mic);
}

void RSNEAPOL::wpa_length(uint16_t length) {
    header_.wpa_length = Endian::host_to_be(length);
}

void RSNEAPOL::key_iv(const uint8_t* ptr) {
    copy(ptr, ptr + sizeof(header_.key_iv), header_.key_iv);
}

void RSNEAPOL::key_length(uint16_t length) {
    header_.key_length = Endian::host_to_be(length);
}

void RSNEAPOL::key(const key_type& value) {
    key_ = value;
}

void RSNEAPOL::key_mic(small_uint<1> flag) {
    header_.key_mic = flag;
}

void RSNEAPOL::secure(small_uint<1> flag) {
    header_.secure = flag;
}

void RSNEAPOL::error(small_uint<1> flag) {
    header_.error = flag;
}

void RSNEAPOL::request(small_uint<1> flag) {
    header_.request = flag;
}

void RSNEAPOL::encrypted(small_uint<1> flag) {
    header_.encrypted = flag;
}

void RSNEAPOL::key_descriptor(small_uint<3> new_key_descriptor) {
    header_.key_descriptor = new_key_descriptor;
}

void RSNEAPOL::key_t(small_uint<1> flag) {
    header_.key_t = flag;
}

void RSNEAPOL::key_index(small_uint<2> value) {
    header_.key_index = value;
}

void RSNEAPOL::install(small_uint<1> flag) {
    header_.install = flag;
}

void RSNEAPOL::key_ack(small_uint<1> flag) {
    header_.key_ack = flag;
}

uint32_t RSNEAPOL::header_size() const {
    return static_cast<uint32_t>(sizeof(eapol_header) + sizeof(header_) + key_.size());
}

void RSNEAPOL::write_body(OutputMemoryStream& stream) {
    if (key_.size()) {
        if (!header_.key_t && header_.install) {
            header_.key_length = Endian::host_to_be<uint16_t>(32);
            wpa_length(static_cast<uint16_t>(key_.size()));
        }
        else if (key_.size()) {
            wpa_length(static_cast<uint16_t>(key_.size()));
        }
    }
    stream.write(header_);
    stream.write(key_.begin(), key_.end());
}

} // Tins
