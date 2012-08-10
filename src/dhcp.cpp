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
#include "ethernetII.h"

using std::string;
using std::list;
using std::runtime_error;

namespace Tins {
const uint32_t DHCP::MAX_DHCP_SIZE = 312;

/* Magic cookie: uint32_t.
 * end of options: 1 byte. */
DHCP::DHCP() : _size(sizeof(uint32_t) + 1) {
    opcode(BOOTREQUEST);
    htype(1); //ethernet
    hlen(EthernetII::ADDR_SIZE);
}

DHCP::DHCP(const uint8_t *buffer, uint32_t total_sz) 
: BootP(buffer, total_sz, 0), _size(sizeof(uint32_t) + 1)
{
    buffer += BootP::header_size() - vend_size();
    total_sz -= BootP::header_size() - vend_size();
    uint8_t args[2] = {0};
    if(total_sz < sizeof(uint32_t) || *(uint32_t*)buffer != Utils::net_to_host_l(0x63825363))
        throw std::runtime_error("Not enough size for a DHCP header in the buffer.");
    buffer += sizeof(uint32_t);
    total_sz -= sizeof(uint32_t);
    while(total_sz) {
        for(unsigned i(0); i < 2; ++i) {
            args[i] = *(buffer++);
            total_sz--;
            if(args[0] == END || args[0] == PAD)
                i = 2;
            else if(!total_sz)
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

DHCP::DHCPOption::DHCPOption(uint8_t opt, uint8_t len, const uint8_t *val) 
: option(opt), value(val, val ? (val + len) : val) {

}

bool DHCP::add_option(Options opt, uint8_t len, const uint8_t *val) {
    uint32_t opt_size = len + (sizeof(uint8_t) << 1);
    if(_size + opt_size > MAX_DHCP_SIZE)
        return false;
    _options.push_back(DHCPOption((uint8_t)opt, len, val));
    _size += opt_size;
    return true;
}

const DHCP::DHCPOption *DHCP::search_option(Options opt) const{
    for(options_type::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        if(it->option == opt)
            return &(*it);
    }
    return 0;
}

bool DHCP::add_type_option(Flags type) {
    return add_option(DHCP_MESSAGE_TYPE, sizeof(uint8_t), (const uint8_t*)&type);
}

bool DHCP::search_type_option(uint8_t *value) {
    return generic_search(DHCP_MESSAGE_TYPE, value);
}

bool DHCP::add_server_identifier(uint32_t ip) {
    ip = Utils::net_to_host_l(ip);
    return add_option(DHCP_SERVER_IDENTIFIER, sizeof(uint32_t), (const uint8_t*)&ip);
}

bool DHCP::search_server_identifier(uint32_t *value) {
    return generic_search(DHCP_SERVER_IDENTIFIER, value);
}

bool DHCP::add_lease_time(uint32_t time) {
    time = Utils::net_to_host_l(time);
    return add_option(DHCP_LEASE_TIME, sizeof(uint32_t), (const uint8_t*)&time);
}

bool DHCP::search_lease_time(uint32_t *value) {
    return generic_search(DHCP_LEASE_TIME, value);
}

bool DHCP::add_renewal_time(uint32_t time) {
    time = Utils::net_to_host_l(time);
    return add_option(DHCP_RENEWAL_TIME, sizeof(uint32_t), (const uint8_t*)&time);
}
        
bool DHCP::search_renewal_time(uint32_t *value) {
    return generic_search(DHCP_RENEWAL_TIME, value);
}

bool DHCP::add_subnet_mask(uint32_t mask) {
    mask = Utils::net_to_host_l(mask);
    return add_option(SUBNET_MASK, sizeof(uint32_t), (const uint8_t*)&mask);
}

bool DHCP::search_subnet_mask(uint32_t *value) {
    return generic_search(SUBNET_MASK, value);
}

bool DHCP::add_routers_option(const list<uint32_t> &routers) {
    uint32_t size;
    uint8_t *buffer = serialize_list(routers, size);
    bool ret = add_option(ROUTERS, size, buffer);
    delete[] buffer;
    return ret;
}

bool DHCP::search_routers_option(std::list<uint32_t> *routers) {
    return generic_search(ROUTERS, routers);
}

bool DHCP::add_dns_option(const list<uint32_t> &dns) {
    uint32_t size;
    uint8_t *buffer = serialize_list(dns, size);
    bool ret = add_option(DOMAIN_NAME_SERVERS, size, buffer);
    delete[] buffer;
    return ret;
}

bool DHCP::search_dns_option(std::list<uint32_t> *dns) {
    return generic_search(DOMAIN_NAME_SERVERS, dns);
}

bool DHCP::add_broadcast_option(uint32_t addr) {
    addr = Utils::net_to_host_l(addr);
    return add_option(BROADCAST_ADDRESS, sizeof(uint32_t), (uint8_t*)&addr);
}

bool DHCP::search_broadcast_option(uint32_t *value) {
    return generic_search(BROADCAST_ADDRESS, value);
}

bool DHCP::add_requested_ip_option(uint32_t addr) {
    addr = Utils::net_to_host_l(addr);
    return add_option(DHCP_REQUESTED_ADDRESS, sizeof(uint32_t), (uint8_t*)&addr);
}

bool DHCP::search_requested_ip_option(uint32_t *value) {
    return generic_search(DHCP_REQUESTED_ADDRESS, value);
}

bool DHCP::add_domain_name(const string &name) {
    return add_option(DOMAIN_NAME, name.size(), (const uint8_t*)name.c_str());
}

bool DHCP::search_domain_name(std::string *value) {
    return generic_search(DOMAIN_NAME, value);
}

bool DHCP::add_rebind_time(uint32_t time) {
    time = Utils::net_to_host_l(time);
    return add_option(DHCP_REBINDING_TIME, sizeof(uint32_t), (uint8_t*)&time);
}
        
bool DHCP::search_rebind_time(uint32_t *value) {
    return generic_search(DHCP_REBINDING_TIME, value);
}

uint8_t *DHCP::serialize_list(const list<uint32_t> &int_list, uint32_t &sz) {
    uint8_t *buffer = new uint8_t[int_list.size() * sizeof(uint32_t)];
    uint32_t *ptr = (uint32_t*)buffer;
    for(list<uint32_t>::const_iterator it = int_list.begin(); it != int_list.end(); ++it)
        *(ptr++) = Utils::net_to_host_l(*it);
    sz = sizeof(uint32_t) * int_list.size();
    return buffer;
}

uint32_t DHCP::header_size() const {
    return BootP::header_size() - vend_size() + _size;
}

void DHCP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= header_size());
    uint8_t *result = 0;
    if(_size) {
        result = new uint8_t[_size];
        uint8_t *ptr = result + sizeof(uint32_t);
        // Magic cookie
        *((uint32_t*)result) = Utils::net_to_host_l(0x63825363);
        for(options_type::const_iterator it = _options.begin(); it != _options.end(); ++it) {
            *(ptr++) = it->option;
            *(ptr++) = it->value.size();
            std::copy(it->value.begin(), it->value.end(), ptr);
            ptr += it->value.size();
        }
        // End of options
        result[_size-1] = END;
        vend(result, _size);
    }
    BootP::write_serialization(buffer, total_sz, parent);
    delete[] result;
}

void DHCP::copy_fields(const DHCP *other) {
    BootP::copy_bootp_fields(other);
    _size = other->_size;
    for(options_type::const_iterator it = other->_options.begin(); it != other->_options.end(); ++it)
        _options.push_back(*it);
}

bool DHCP::generic_search(Options opt, std::list<uint32_t> *container) {
    const DHCPOption *option = search_option(opt);
    if(!option)
        return false;
    const uint32_t *ptr = (const uint32_t*)&option->value[0];
    uint32_t len = option->value.size();
    if((len % sizeof(uint32_t)) != 0)
        return false;
    while(len) {
        container->push_back(Utils::net_to_host_l(*(ptr++)));
        len -= sizeof(uint32_t);
    }
    return true;
}

bool DHCP::generic_search(Options opt, std::string *str) {
    const DHCPOption *option = search_option(opt);
    if(!option)
        return false;
    //*str = string((const char*)option->value, option->length);
    *str = string(option->value.begin(), option->value.end());
    return true;
}

bool DHCP::generic_search(Options opt, uint32_t *value) {
    if(generic_search<uint32_t>(opt, value)) {
        *value = Utils::net_to_host_l(*value);
        return true;
    }
    return false;
}
}
