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
#include <iostream> //borrame
#include "utils.h"
#include "dhcp.h"

const uint32_t Tins::DHCP::MAX_DHCP_SIZE = 312;

/* Magic cookie: uint32_t.
 * end of options: 1 byte. */
Tins::DHCP::DHCP() : _size(sizeof(uint32_t) + 1) {
    opcode(BOOTREQUEST);
    htype(1); //ethernet
    hlen(6);
}

Tins::DHCP::DHCPOption::DHCPOption(uint8_t opt, uint8_t len, uint8_t *val) : option(opt), length(len) {
    value = new uint8_t[len];
    std::memcpy(value, val, len);
}

bool Tins::DHCP::add_option(Options opt, uint8_t len, uint8_t *val) {
    uint32_t opt_size = len + (sizeof(uint8_t) << 1);
    if(_size + opt_size > MAX_DHCP_SIZE)
        return false;
    _options.push_back(DHCPOption((uint8_t)opt, len, val));
    _size += opt_size;
    return true;
}

bool Tins::DHCP::add_type_option(Flags type) {
    return add_option(DHCP_MESSAGE_TYPE, 1, (uint8_t*)&type);
}

bool Tins::DHCP::add_server_identifier(uint32_t ip) {
    return add_option(DHCP_SERVER_IDENTIFIER, 4, (uint8_t*)&ip);
}

bool Tins::DHCP::add_lease_time(uint32_t time) {
    time = Utils::net_to_host_l(time);
    return add_option(DHCP_LEASE_TIME, 4, (uint8_t*)&time);
}

uint32_t Tins::DHCP::header_size() const {
    return BootP::header_size() - vend_size() + _size;
}

void Tins::DHCP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= header_size());
    uint8_t *result = new uint8_t[_size], *ptr = result + sizeof(uint32_t);
    *((uint32_t*)result) = Utils::net_to_host_l(0x63825363);
    for(std::list<DHCPOption>::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        *(ptr++) = it->option;
        *(ptr++) = it->length;
        std::memcpy(ptr, it->value, it->length);
        ptr += it->length;
    }
    result[_size-1] = END;
    vend(result, _size);
    BootP::write_serialization(buffer, total_sz, parent);
    delete[] result;
}

