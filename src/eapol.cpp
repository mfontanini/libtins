/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <cstring>
#include <cassert>
#include <stdexcept>
#include "eapol.h"
#include "dot11.h"


Tins::EAPOL::EAPOL(uint8_t packet_type, EAPOLTYPE type) : PDU(0xff) {
    std::memset(&_header, 0, sizeof(_header));
    _header.version = 1;
    _header.packet_type = packet_type;
    _header.type = (uint8_t)type;
}

Tins::EAPOL::EAPOL(const uint8_t *buffer, uint32_t total_sz) : PDU(0xff) {
    if(total_sz < sizeof(_header))
        throw std::runtime_error("Not enough size for an EAPOL header in the buffer.");
    std::memcpy(&_header, buffer, sizeof(_header));
}

Tins::EAPOL::EAPOL(const EAPOL &other) : PDU(other) {
    copy_eapol_fields(&other);
}

Tins::EAPOL *Tins::EAPOL::from_bytes(const uint8_t *buffer, uint32_t total_sz) {
    if(total_sz < sizeof(eapolhdr))
        throw std::runtime_error("Not enough size for an EAPOL header in the buffer.");
    const eapolhdr *ptr = (const eapolhdr*)buffer;
    switch(ptr->type) {
        case RC4:
            return new RC4EAPOL(buffer, total_sz);
            break;
        case RSN:
        case EAPOL_WPA:
            return new RSNEAPOL(buffer, total_sz);
            break;
    }
    return 0;
}

void Tins::EAPOL::version(uint8_t new_version) {
    _header.version = new_version;
}
        
void Tins::EAPOL::packet_type(uint8_t new_ptype) {
    _header.packet_type = new_ptype;
}

void Tins::EAPOL::length(uint8_t new_length) {
    _header.length = Utils::net_to_host_s(new_length);
}

void Tins::EAPOL::type(uint8_t new_type) {
    _header.type = new_type;
}

void Tins::EAPOL::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    uint32_t sz = header_size();
    assert(total_sz >= sz);
    if(!_header.length)
        length(sz - sizeof(_header.version) - sizeof(_header.length) - sizeof(_header.type));
    std::memcpy(buffer, &_header, sizeof(_header));
    write_body(buffer + sizeof(_header), total_sz - sizeof(_header));
}

void Tins::EAPOL::copy_eapol_fields(const EAPOL *other) {
    std::memcpy(&_header, &other->_header, sizeof(_header));
    
}

/* RC4EAPOL */

Tins::RC4EAPOL::RC4EAPOL() : EAPOL(0x03, RC4), _key(0), _key_size(0) {
    std::memset(&_header, 0, sizeof(_header));
}

Tins::RC4EAPOL::RC4EAPOL(const uint8_t *buffer, uint32_t total_sz) : EAPOL(buffer, total_sz), _key_size(0) {
    buffer += sizeof(eapolhdr);
    total_sz -= sizeof(eapolhdr);
    if(total_sz < sizeof(_header))
        throw std::runtime_error("Not enough size for an EAPOL header in the buffer.");
    std::memcpy(&_header, buffer, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    if(total_sz == key_length()) {
        _key = new uint8_t[total_sz];
        _key_size = total_sz;
        std::memcpy(_key, buffer, total_sz);
    }
    else 
        _key = 0;
}

Tins::RC4EAPOL::RC4EAPOL(const RC4EAPOL &other) : EAPOL(other) {
    copy_fields(&other);
}

Tins::RC4EAPOL &Tins::RC4EAPOL::operator= (const RC4EAPOL &other) {
    copy_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

Tins::RC4EAPOL::~RC4EAPOL() {
    delete[] _key;
}

void Tins::RC4EAPOL::key_length(uint16_t new_key_length) {
    _header.key_length = Utils::net_to_host_s(new_key_length);
}
        
void Tins::RC4EAPOL::replay_counter(uint16_t new_replay_counter) {
    _header.replay_counter = Utils::net_to_host_s(new_replay_counter);
}

void Tins::RC4EAPOL::key_iv(const uint8_t *new_key_iv) {
    std::memcpy(_header.key_iv, new_key_iv, sizeof(_header.key_iv));
}

void Tins::RC4EAPOL::key_flag(bool new_key_flag) {
    _header.key_flag = new_key_flag;
}

void Tins::RC4EAPOL::key_index(uint8_t new_key_index) {
    _header.key_index = new_key_index;
}

void Tins::RC4EAPOL::key_sign(const uint8_t *new_key_sign) {
    std::memcpy(_header.key_sign, new_key_sign, sizeof(_header.key_sign));
}

void Tins::RC4EAPOL::key(const uint8_t *new_key, uint32_t sz) {
    delete[] _key;
    _key = new uint8_t[sz];
    _key_size = sz;
    std::memcpy(_key, new_key, sz);
}

uint32_t Tins::RC4EAPOL::header_size() const {
    return sizeof(eapolhdr) + sizeof(_header) + _key_size;
}

void Tins::RC4EAPOL::write_body(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(_header) + _key_size;
    assert(total_sz >= sz);
    if(_key)
        _header.key_length = Utils::net_to_host_s(_key_size);
    std::memcpy(buffer, &_header, sizeof(_header));
    buffer += sizeof(_header);
    if(_key)
        std::memcpy(buffer, _key, _key_size);
}

Tins::PDU *Tins::RC4EAPOL::clone_pdu() const {
    RC4EAPOL *new_pdu = new RC4EAPOL();
    new_pdu->copy_fields(this);
    return new_pdu;
}

void Tins::RC4EAPOL::copy_fields(const RC4EAPOL *other) {
    copy_eapol_fields(other);
    std::memcpy(&_header, &other->_header, sizeof(_header));
    _key_size = other->_key_size;
    if(_key_size) {
        _key = new uint8_t[_key_size];
        std::memcpy(_key, other->_key, _key_size);
    }
    else
        _key = 0;
}

/* RSNEAPOL */


Tins::RSNEAPOL::RSNEAPOL() : EAPOL(0x03, RSN), _key(0), _key_size(0) {
    std::memset(&_header, 0, sizeof(_header));
}

Tins::RSNEAPOL::RSNEAPOL(const uint8_t *buffer, uint32_t total_sz) : EAPOL(0x03, RSN), _key_size(0) {
    buffer += sizeof(eapolhdr);
    total_sz -= sizeof(eapolhdr);
    if(total_sz < sizeof(_header))
        throw std::runtime_error("Not enough size for an EAPOL header in the buffer.");
    std::memcpy(&_header, buffer, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    if(total_sz == wpa_length()) {
        _key = new uint8_t[total_sz];
        _key_size = total_sz;
        std::memcpy(_key, buffer, total_sz);
    }
    else 
        _key = 0;
}

Tins::RSNEAPOL::RSNEAPOL(const RSNEAPOL &other) : EAPOL(other) {
    copy_fields(&other);
}

Tins::RSNEAPOL &Tins::RSNEAPOL::operator= (const RSNEAPOL &other) {
    copy_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

Tins::RSNEAPOL::~RSNEAPOL() {
    delete[] _key;
}

void Tins::RSNEAPOL::RSNEAPOL::nonce(const uint8_t *new_nonce) {
    std::memcpy(_header.nonce, new_nonce, sizeof(_header.nonce));
}

void Tins::RSNEAPOL::rsc(uint64_t new_rsc) {
    _header.rsc = Utils::net_to_host_ll(new_rsc);
}

void Tins::RSNEAPOL::id(uint64_t new_id) {
    _header.id = Utils::net_to_host_ll(new_id);
}

void Tins::RSNEAPOL::mic(const uint8_t *new_mic) {
    std::memcpy(_header.mic, new_mic, sizeof(_header.mic));
}

void Tins::RSNEAPOL::wpa_length(uint16_t new_wpa_length) {
    _header.wpa_length = Utils::net_to_host_s(new_wpa_length);
}

void Tins::RSNEAPOL::key(const uint8_t *new_key, uint32_t sz) {
    delete[] _key;
    _key = new uint8_t[sz];
    _key_size = sz;
    _header.key_type = 0;
    std::memcpy(_key, new_key, sz);
}

void Tins::RSNEAPOL::rsn_information(const RSNInformation &rsn) {
    _key = rsn.serialize(_key_size);
    _header.key_type = 1;
}

uint32_t Tins::RSNEAPOL::header_size() const {
    uint32_t padding(0);
    if(_header.key_type && _key_size)
        padding = 2;
    return sizeof(eapolhdr) + sizeof(_header) + _key_size + padding;
}

void Tins::RSNEAPOL::write_body(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = header_size() - sizeof(eapolhdr);
    assert(total_sz >= sz);
    if(_key) {
        if(!_header.key_type) {
            _header.key_length = Utils::net_to_host_s(32);
            wpa_length(_key_size);
        }
        else if(_key_size) {
            _header.key_length = 0;
            wpa_length(_key_size + 2);
        }
        else
            wpa_length(0);
    }
    std::memcpy(buffer, &_header, sizeof(_header));
    buffer += sizeof(_header);
    if(_key) {
        if(_header.key_type && _key_size) {
            *(buffer++) = Dot11::RSN;
            *(buffer++) = _key_size;
        }
        std::memcpy(buffer, _key, _key_size);
    }
}

void Tins::RSNEAPOL::copy_fields(const RSNEAPOL *other) {
    copy_eapol_fields(other);
    std::memcpy(&_header, &other->_header, sizeof(_header));
    _key_size = other->_key_size;
    if(_key_size) {
        _key = new uint8_t[_key_size];
        std::memcpy(_key, other->_key, _key_size);
    }
    else
        _key = 0;
}

Tins::PDU *Tins::RSNEAPOL::clone_pdu() const {
    RSNEAPOL *new_pdu = new RSNEAPOL();
    new_pdu->copy_fields(this);
    return new_pdu;
}
