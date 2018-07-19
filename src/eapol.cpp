/*
 * Copyright (c) 2017, Matias Fontanini
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
#include <tins/eapol.h>
#include <tins/exceptions.h>
#include <tins/rawpdu.h>
#include <tins/memory_helpers.h>

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
    const uint32_t actual_size = (total_sz < advertised_size) ? total_sz : advertised_size;
    return metadata(actual_size, pdu_flag, PDU::UNKNOWN);
}

EAPOL::EAPOL(PacketTypes packet_type)
: header_() {
    header_.version = 1;
    header_.packet_type = packet_type;
}

EAPOL::EAPOL(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
}

EAPOL* EAPOL::from_bytes(const uint8_t* buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(eapol_header))) {
        throw malformed_packet();
    }
    const eapol_header* eapol_ptr = (const eapol_header*)buffer;

    uint32_t data_len = Endian::be_to_host<uint16_t>(eapol_ptr->length);
    // at least 4 for fields always present
    data_len += 4;
    total_sz = (total_sz < data_len) ? total_sz : data_len;

    switch(eapol_ptr->packet_type) {
    case START:
    case LOGOFF:
        return new Tins::EAPOL(buffer, total_sz);
        break;
    case EAP_TYPE:
        return new Tins::Eap(buffer, total_sz);
        break;
    case KEY:
        const overlapping_eapol_header* ov_eapol_ptr = (const overlapping_eapol_header*)buffer;
        switch(ov_eapol_ptr->subtype_code) {
            case RC4:
                return new Tins::RC4EAPOL(buffer, total_sz);
                break;
            case RSN:
            case EAPOL_WPA:
                return new Tins::RSNEAPOL(buffer, total_sz);
                break;
        }
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

uint32_t EAPOL::header_size() const {
    return static_cast<uint32_t>(sizeof(eapol_header));
}

void EAPOL::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);
    length(size() - 4);
    stream.write(header_);
    memcpy(buffer, &header_, sizeof(header_));
    write_body(stream);
}

void EAPOL::write_body(Memory::OutputMemoryStream& ) {
    //write nothing
}

/* EAP */

Eap::Eap()
: EAPOL(EAP_TYPE) {
    memset(&eap_header_, 0, sizeof(eap_header_));
    eap_header_.code = SUCCESS;
    length(size() - 4);
}

Eap::Eap(Codes eap_code)
: EAPOL(EAP_TYPE) {
    init(eap_code, 0 , invalid_type);
}
Eap::Eap(Codes eap_code, uint8_t id)
: EAPOL(EAP_TYPE) {
    init(eap_code, id , invalid_type);
}

Eap::Eap(Codes eap_code, uint8_t id, uint8_t eap_type)
: EAPOL(EAP_TYPE) {
    init(eap_code, id , eap_type);
}

Eap::Eap(const uint8_t* buffer, uint32_t total_sz)
: EAPOL(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(sizeof(eapol_header));
    eap_header eap_header_tmp;
    stream.read(eap_header_tmp);
    eap_header_.code = eap_header_tmp.code;
    eap_header_.id = eap_header_tmp.id;
    eap_header_.length = eap_header_tmp.length;
    switch(eap_header_tmp.code) {
    case SUCCESS:
    case FAILURE:
        eap_header_.type = invalid_type;
        break;
    case REQUEST:
    case RESPONSE:
        stream.read(eap_header_.type);
        if (stream) {
            inner_pdu(new RawPDU(stream.pointer(), stream.size()));
        }
        break;
    }
}

void Eap::length(uint16_t new_length) {
    eap_header_.length = Endian::host_to_be(new_length);
    this->EAPOL::length(new_length);
}

void Eap::code(Codes new_code) {
    eap_header_.code = static_cast<uint8_t>(new_code);
    switch(new_code) {
        case SUCCESS:
        case FAILURE:
            type(invalid_type);
            break;
        case REQUEST:
        case RESPONSE:
            break;
        }
}

void Eap::id(uint8_t new_id) {
    eap_header_.id = new_id;
}

void Eap::type(uint8_t new_type) {
    eap_header_.type = new_type;
}

uint32_t Eap::header_size() const {
    if(eap_header_.type == invalid_type) {
        return  static_cast<uint32_t>(sizeof(eapol_header)) + sizeof(eap_header_) - 1;
    }
    else {
        return  static_cast<uint32_t>(sizeof(eapol_header)) + sizeof(eap_header_);
    }
}

void Eap::write_body(OutputMemoryStream& stream) {
    stream.write(eap_header_.code);
    stream.write(eap_header_.id);
    stream.write(eap_header_.length);
    if(eap_header_.type != invalid_type) {
        stream.write(eap_header_.type);
    }
}

void Eap::init(Codes eap_code, uint8_t id, uint8_t eap_type) {
    eap_header_.code = eap_code;
    eap_header_.type = eap_type;
    eap_header_.id = id;
    length(size() - 4);
}

/* RC4EAPOL */

RC4EAPOL::RC4EAPOL() 
: EAPOL(KEY) {
    memset(&header_, 0, sizeof(header_));
    header_.type = RC4;
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
    memcpy(header_.key_iv, ptr, sizeof(header_.key_iv));
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
: EAPOL(KEY) {
    memset(&header_, 0, sizeof(header_));
    header_.type = RSN;
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
    memcpy(header_.nonce, ptr, nonce_size);
}

void RSNEAPOL::rsc(const uint8_t* ptr) {
    memcpy(header_.rsc, ptr, rsc_size);
}

void RSNEAPOL::id(const uint8_t* ptr) {
    memcpy(header_.id, ptr, id_size);
}

void RSNEAPOL::replay_counter(uint64_t new_replay_counter) {
    header_.replay_counter = Endian::host_to_be(new_replay_counter);
}

void RSNEAPOL::mic(const uint8_t* ptr) {
    memcpy(header_.mic, ptr, mic_size);
}

void RSNEAPOL::wpa_length(uint16_t length) {
    header_.wpa_length = Endian::host_to_be(length);
}

void RSNEAPOL::key_iv(const uint8_t* ptr) {
    memcpy(header_.key_iv, ptr, sizeof(header_.key_iv));
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
