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
#include <cstring>
#include <cassert>
#include "utils.h"
#include "dhcp.h"

const uint32_t Tins::DHCP::MAX_DHCP_SIZE = 312;

using namespace std;

/* Magic cookie: uint32_t.
 * end of options: 1 byte. */
Tins::DHCP::DHCP() : _size(sizeof(uint32_t) + 1) {
    opcode(BOOTREQUEST);
    htype(1); //ethernet
    hlen(6);
}

Tins::DHCP::DHCP(const uint8_t *buffer, uint32_t total_sz) : BootP(buffer, total_sz, 0) {
    buffer += BootP::header_size();
    total_sz -= BootP::header_size();
    uint8_t args[2] = {0};
    while(total_sz) {
        for(unsigned i(0); i < 2 && args[0] != END && args[0] != PAD; ++i) {
            args[i] = *(buffer++);
            total_sz--;
            if(!total_sz)
                throw std::runtime_error("Not enough size for a DHCP header in the buffer.");
        }
        // If the END-OF-OPTIONS was not found...
        if(args[0] != END && args[0] != PAD) {            
            // Not enough size for this option
            if(total_sz < args[1])
                throw std::runtime_error("Not enough size for a DHCP header in the buffer.");
            add_option((Options)args[0], args[1], buffer);
            buffer += args[1];
            total_sz -= args[1];
        }
        // Otherwise, break the loop.
        else
            total_sz = 0;
    }
}

Tins::DHCP::DHCP(const DHCP &other) : BootP(other) {
    copy_fields(&other);
}

Tins::DHCP &Tins::DHCP::operator= (const DHCP &other) {
    copy_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

Tins::DHCP::~DHCP() {
    while(_options.size()) {
        delete[] _options.front().value;
        _options.pop_front();
    }
}

Tins::DHCP::DHCPOption::DHCPOption(uint8_t opt, uint8_t len, const uint8_t *val) : option(opt), length(len) {
    if(len) {
        value = new uint8_t[len];    
        std::memcpy(value, val, len);
    }
    else
        value = 0;
}

bool Tins::DHCP::add_option(Options opt, uint8_t len, const uint8_t *val) {
    uint32_t opt_size = len + (sizeof(uint8_t) << 1);
    if(_size + opt_size > MAX_DHCP_SIZE)
        return false;
    _options.push_back(DHCPOption((uint8_t)opt, len, val));
    _size += opt_size;
    return true;
}

bool Tins::DHCP::add_type_option(Flags type) {
    return add_option(DHCP_MESSAGE_TYPE, 1, (const uint8_t*)&type);
}

bool Tins::DHCP::add_server_identifier(uint32_t ip) {
    return add_option(DHCP_SERVER_IDENTIFIER, 4, (const uint8_t*)&ip);
}

bool Tins::DHCP::add_lease_time(uint32_t time) {
    time = Utils::net_to_host_l(time);
    return add_option(DHCP_LEASE_TIME, 4, (const uint8_t*)&time);
}

bool Tins::DHCP::add_subnet_mask(uint32_t mask) {
    return add_option(SUBNET_MASK, 4, (const uint8_t*)&mask);
}

bool Tins::DHCP::add_routers_option(const list<uint32_t> &routers) {
    uint32_t size;
    uint8_t *buffer = serialize_list(routers, size);
    bool ret = add_option(ROUTERS, size, buffer);
    delete[] buffer;
    return ret;
}

bool Tins::DHCP::add_dns_options(const list<uint32_t> &dns) {
    uint32_t size;
    uint8_t *buffer = serialize_list(dns, size);
    bool ret = add_option(DOMAIN_NAME_SERVERS, size, buffer);
    delete[] buffer;
    return ret;
}

bool Tins::DHCP::add_broadcast_option(uint32_t addr) {
    return add_option(BROADCAST_ADDRESS, 4, (uint8_t*)&addr);
}

bool Tins::DHCP::add_domain_name(const string &name) {
    return add_option(DOMAIN_NAME, name.size(), (const uint8_t*)name.c_str());
}

uint8_t *Tins::DHCP::serialize_list(const list<uint32_t> &int_list, uint32_t &sz) {
    uint8_t *buffer = new uint8_t[int_list.size() * sizeof(uint32_t)];
    uint32_t *ptr = (uint32_t*)buffer;
    for(list<uint32_t>::const_iterator it = int_list.begin(); it != int_list.end(); ++it)
        *(ptr++) = *it;
    sz = sizeof(uint32_t) * int_list.size();
    return buffer;
}

uint32_t Tins::DHCP::header_size() const {
    return BootP::header_size() - vend_size() + _size;
}

void Tins::DHCP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= header_size());
    uint8_t *result = 0;
    if(_size) {
        result = new uint8_t[_size];
        uint8_t *ptr = result + sizeof(uint32_t);
        // Magic cookie
        *((uint32_t*)result) = Utils::net_to_host_l(0x63825363);
        for(std::list<DHCPOption>::const_iterator it = _options.begin(); it != _options.end(); ++it) {
            *(ptr++) = it->option;
            *(ptr++) = it->length;
            if(it->length)
                std::memcpy(ptr, it->value, it->length);
            ptr += it->length;
        }
        // End of options
        result[_size-1] = END;
        vend(result, _size);
    }
    BootP::write_serialization(buffer, total_sz, parent);
    delete[] result;
}

void Tins::DHCP::copy_fields(const DHCP *other) {
    BootP::copy_bootp_fields(other);
    _size = other->_size;
    for(std::list<DHCPOption>::const_iterator it = other->_options.begin(); it != other->_options.end(); ++it)
        _options.push_back(DHCPOption(it->option, it->length, it->value));
}

Tins::PDU *Tins::DHCP::clone_pdu() const {
    DHCP *new_pdu = new DHCP();
    new_pdu->copy_fields(this);
    return new_pdu;
}
