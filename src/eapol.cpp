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

#include <cstring>
#ifdef TINS_DEBUG
#include <cassert>
#endif
#include <stdexcept>
#include <algorithm>
#include "eapol.h"
#include "rsn_information.h"
#include "exceptions.h"

namespace Tins {
EAPOL::EAPOL(uint8_t packet_type, EAPOLTYPE type) 
{
    std::memset(&_header, 0, sizeof(_header));
    _header.version = 1;
    _header.packet_type = packet_type;
    _header.type = (uint8_t)type;
}

EAPOL::EAPOL(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(_header))
        throw malformed_packet();
    std::memcpy(&_header, buffer, sizeof(_header));
}

EAPOL *EAPOL::from_bytes(const uint8_t *buffer, uint32_t total_sz) {
    if(total_sz < sizeof(eapolhdr))
        throw malformed_packet();
    const eapolhdr *ptr = (const eapolhdr*)buffer;
    uint32_t data_len = Endian::be_to_host<uint16_t>(ptr->length);
    // at least 4 for fields always present
    total_sz = std::min(
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
    _header.version = new_version;
}
        
void EAPOL::packet_type(uint8_t new_ptype) {
    _header.packet_type = new_ptype;
}

void EAPOL::length(uint16_t new_length) {
    _header.length = Endian::host_to_be(new_length);
}

void EAPOL::type(uint8_t new_type) {
    _header.type = new_type;
}

void EAPOL::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    #ifdef TINS_DEBUG
    assert(total_sz >= header_size());
    #endif
    std::memcpy(buffer, &_header, sizeof(_header));
    write_body(buffer + sizeof(_header), total_sz - sizeof(_header));
}

/* RC4EAPOL */

RC4EAPOL::RC4EAPOL() 
: EAPOL(0x03, RC4) 
{
    std::memset(&_header, 0, sizeof(_header));
}

RC4EAPOL::RC4EAPOL(const uint8_t *buffer, uint32_t total_sz) 
: EAPOL(buffer, total_sz)
{
    buffer += sizeof(eapolhdr);
    total_sz -= sizeof(eapolhdr);
    if(total_sz < sizeof(_header))
        throw malformed_packet();
    std::memcpy(&_header, buffer, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    if(total_sz == key_length())
        _key.assign(buffer, buffer + total_sz);
}

void RC4EAPOL::key_length(uint16_t new_key_length) {
    _header.key_length = Endian::host_to_be(new_key_length);
}
        
void RC4EAPOL::replay_counter(uint64_t new_replay_counter) {
    _header.replay_counter = Endian::host_to_be(new_replay_counter);
}

void RC4EAPOL::key_iv(const uint8_t *new_key_iv) {
    std::copy(new_key_iv, new_key_iv + sizeof(_header.key_iv), _header.key_iv);
}

void RC4EAPOL::key_flag(small_uint<1> new_key_flag) {
    _header.key_flag = new_key_flag;
}

void RC4EAPOL::key_index(small_uint<7> new_key_index) {
    _header.key_index = new_key_index;
}

void RC4EAPOL::key_sign(const uint8_t *new_key_sign) {
    std::memcpy(_header.key_sign, new_key_sign, sizeof(_header.key_sign));
}

void RC4EAPOL::key(const key_type &new_key) {
    _key = new_key;
}

uint32_t RC4EAPOL::header_size() const {
    return sizeof(eapolhdr) + sizeof(_header) + _key.size();
}

void RC4EAPOL::write_body(uint8_t *buffer, uint32_t total_sz) {
    #ifdef TINS_DEBUG
    assert(total_sz >= sizeof(_header) + _key.size());
    #endif
    if(_key.size())
        _header.key_length = Endian::host_to_be(_key.size());
    std::memcpy(buffer, &_header, sizeof(_header));
    buffer += sizeof(_header);
    std::copy(_key.begin(), _key.end(), buffer);
}

/* RSNEAPOL */


RSNEAPOL::RSNEAPOL() 
: EAPOL(0x03, RSN) 
{
    std::memset(&_header, 0, sizeof(_header));
}

RSNEAPOL::RSNEAPOL(const uint8_t *buffer, uint32_t total_sz) 
: EAPOL(buffer, total_sz)
{
    buffer += sizeof(eapolhdr);
    total_sz -= sizeof(eapolhdr);
    if(total_sz < sizeof(_header))
        throw malformed_packet();
    std::memcpy(&_header, buffer, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    if(total_sz == wpa_length())
        _key.assign(buffer, buffer + total_sz);
}

void RSNEAPOL::nonce(const uint8_t *new_nonce) {
    std::copy(new_nonce, new_nonce + nonce_size, _header.nonce);
}

void RSNEAPOL::rsc(const uint8_t *new_rsc) {
    std::copy(new_rsc, new_rsc + rsc_size, _header.rsc);
}

void RSNEAPOL::id(const uint8_t *new_id) {
    std::copy(new_id, new_id + id_size, _header.id);
}

void RSNEAPOL::replay_counter(uint64_t new_replay_counter) {
    _header.replay_counter = Endian::host_to_be(new_replay_counter);
}

void RSNEAPOL::mic(const uint8_t *new_mic) {
    std::copy(new_mic, new_mic + mic_size, _header.mic);
}

void RSNEAPOL::wpa_length(uint16_t new_wpa_length) {
    _header.wpa_length = Endian::host_to_be(new_wpa_length);
}

void RSNEAPOL::key_iv(const uint8_t *new_key_iv) {
    std::copy(new_key_iv, new_key_iv + sizeof(_header.key_iv), _header.key_iv);
}

void RSNEAPOL::key_length(uint16_t new_key_length) {
    _header.key_length = Endian::host_to_be(new_key_length);
}

void RSNEAPOL::key(const key_type &new_key) {
    _key = new_key;
    _header.key_t = 0;
}

void RSNEAPOL::key_mic(small_uint<1> new_key_mic) {
    _header.key_mic = new_key_mic;
}

void RSNEAPOL::secure(small_uint<1> new_secure) {
    _header.secure = new_secure;
}

void RSNEAPOL::error(small_uint<1> new_error) {
    _header.error = new_error;
}

void RSNEAPOL::request(small_uint<1> new_request) {
    _header.request = new_request;
}

void RSNEAPOL::encrypted(small_uint<1 > new_encrypted) {
    _header.encrypted = new_encrypted;
}

void RSNEAPOL::key_descriptor(small_uint<3> new_key_descriptor) {
    _header.key_descriptor = new_key_descriptor;
}

void RSNEAPOL::key_t(small_uint<1> new_key_t) {
    _header.key_t = new_key_t;
}

void RSNEAPOL::key_index(small_uint<2> new_key_index) {
    _header.key_index = new_key_index;
}

void RSNEAPOL::install(small_uint<1> new_install) {
    _header.install = new_install;
}

void RSNEAPOL::key_ack(small_uint<1> new_key_ack) {
    _header.key_ack = new_key_ack;
}

uint32_t RSNEAPOL::header_size() const {
    return sizeof(eapolhdr) + sizeof(_header) + _key.size();
}

void RSNEAPOL::write_body(uint8_t *buffer, uint32_t total_sz) {
    #ifdef TINS_DEBUG
    assert(total_sz >= header_size() - sizeof(eapolhdr));
    #endif
    if(_key.size()) {
        if(!_header.key_t) {
            _header.key_length = Endian::host_to_be<uint16_t>(32);
            wpa_length(_key.size());
        }
        else if(_key.size()) {
            wpa_length(_key.size());
        }
    }
    std::memcpy(buffer, &_header, sizeof(_header));
    buffer += sizeof(_header);
    std::copy(_key.begin(), _key.end(), buffer);
}
}
