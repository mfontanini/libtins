/*
 * Copyright (c) 2012, Matias Fontanini
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
#include "rsn_information.h"
#include "exceptions.h"

namespace Tins {
template<typename T>
void check_size(uint32_t total_sz) {
    if(total_sz < sizeof(T))
        throw malformed_packet();
}
    
RSNInformation::RSNInformation() : _version(1), _capabilities(0) {

}

RSNInformation::RSNInformation(const serialization_type &buffer) {
    init(&buffer[0], buffer.size());
}

RSNInformation::RSNInformation(const uint8_t *buffer, uint32_t total_sz) {
    init(buffer, total_sz);
}

void RSNInformation::init(const uint8_t *buffer, uint32_t total_sz) {
    if(total_sz <= sizeof(uint16_t) * 2 + sizeof(uint32_t))
        throw malformed_packet();
    version(Endian::le_to_host(*(uint16_t*)buffer));
    buffer += sizeof(uint16_t);
    total_sz -= sizeof(uint16_t);
    
    group_suite((RSNInformation::CypherSuites)*(uint32_t*)buffer);
    buffer += sizeof(uint32_t);
    total_sz -= sizeof(uint32_t);

    uint16_t count = *(uint16_t*)buffer;
    buffer += sizeof(uint16_t);
    total_sz -= sizeof(uint16_t);
    
    if(count * sizeof(uint32_t) > total_sz)
        throw malformed_packet();
    total_sz -= count * sizeof(uint32_t);
    while(count--) {
        add_pairwise_cypher((RSNInformation::CypherSuites)*(uint32_t*)buffer);
        buffer += sizeof(uint32_t);
    }
    check_size<uint16_t>(total_sz);

    count = *(uint16_t*)buffer;
    buffer += sizeof(uint16_t);
    total_sz -= sizeof(uint16_t);
    if(count * sizeof(uint32_t) > total_sz)
        throw malformed_packet();
    total_sz -= count * sizeof(uint32_t);
    while(count--) {
        add_akm_cypher((RSNInformation::AKMSuites)*(uint32_t*)buffer);
        buffer += sizeof(uint32_t);
    }
    check_size<uint16_t>(total_sz);
    
    capabilities(Endian::le_to_host(*(uint16_t*)buffer));
}

void RSNInformation::add_pairwise_cypher(CypherSuites cypher) {
    _pairwise_cyphers.push_back(cypher);
}

void RSNInformation::add_akm_cypher(AKMSuites akm) {
    _akm_cyphers.push_back(akm);
}

void RSNInformation::group_suite(CypherSuites group) {
    _group_suite = group;
}

void RSNInformation::version(uint16_t ver) {
    _version = Endian::host_to_le(ver);
}

void RSNInformation::capabilities(uint16_t cap) {
    _capabilities = Endian::host_to_le(cap);
}

RSNInformation::serialization_type RSNInformation::serialize() const {
    uint32_t size = sizeof(_version) + sizeof(_capabilities) + sizeof(uint32_t);
    size += (sizeof(uint16_t) << 1); // 2 lists count.
    size += sizeof(uint32_t) * (_akm_cyphers.size() + _pairwise_cyphers.size());
    
    serialization_type buffer(size);
    serialization_type::value_type *ptr = &buffer[0];
    *(uint16_t*)ptr = _version;
    ptr += sizeof(_version);
    *(uint32_t*)ptr = _group_suite;
    ptr += sizeof(uint32_t);
    *(uint16_t*)ptr = _pairwise_cyphers.size();
    ptr += sizeof(uint16_t);
    for(cyphers_type::const_iterator it = _pairwise_cyphers.begin(); it != _pairwise_cyphers.end(); ++it) {
        *(uint32_t*)ptr = *it;
        ptr += sizeof(uint32_t);
    }
    *(uint16_t*)ptr = _akm_cyphers.size();
    ptr += sizeof(uint16_t);
    for(akm_type::const_iterator it = _akm_cyphers.begin(); it != _akm_cyphers.end(); ++it) {
        *(uint32_t*)ptr = *it;
        ptr += sizeof(uint32_t);
    }
    *(uint16_t*)ptr = _capabilities;
    return buffer;
}

RSNInformation RSNInformation::wpa2_psk() {
    RSNInformation info;
    info.group_suite(RSNInformation::CCMP);
    info.add_pairwise_cypher(RSNInformation::CCMP);
    info.add_akm_cypher(RSNInformation::PSK);
    return info;
}
}
