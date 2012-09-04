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

#include <stdexcept>
#include "rsn_information.h"

namespace Tins {
RSNInformation::RSNInformation() : _version(1), _capabilities(0) {

}

RSNInformation::RSNInformation(const uint8_t *buffer, uint32_t total_sz) {
    const char *err_msg = "Malformed RSN information structure";
    version(Endian::le_to_host(*(uint16_t*)buffer));
    buffer += sizeof(uint16_t);
    group_suite((RSNInformation::CypherSuites)*(uint32_t*)buffer);
    buffer += sizeof(uint32_t);

    total_sz -= (sizeof(uint16_t) << 1) + sizeof(uint32_t);
    if(total_sz < sizeof(uint16_t))
        throw std::runtime_error(err_msg);
    uint16_t count = *(uint16_t*)buffer;
    buffer += sizeof(uint16_t);
    if(count * sizeof(uint32_t) > total_sz)
        throw std::runtime_error(err_msg);
    total_sz -= count * sizeof(uint32_t);
    while(count--) {
        add_pairwise_cypher((RSNInformation::CypherSuites)*(uint32_t*)buffer);
        buffer += sizeof(uint32_t);
    }
    if(total_sz < sizeof(uint16_t))
        throw std::runtime_error(err_msg);
    count = *(uint16_t*)buffer;
    buffer += sizeof(uint16_t);
    total_sz -= sizeof(uint16_t);
    if(count * sizeof(uint32_t) > total_sz)
        throw std::runtime_error(err_msg);
    total_sz -= count * sizeof(uint32_t);
    while(count--) {
        add_akm_cypher((RSNInformation::AKMSuites)*(uint32_t*)buffer);
        buffer += sizeof(uint32_t);
    }
    if(total_sz < sizeof(uint16_t))
        throw std::runtime_error(err_msg);
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
