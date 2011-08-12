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
#ifndef WIN32
    #include <netinet/in.h>
#endif
#include "ip.h"
#include "utils.h"

#include <iostream>

using namespace std;

const uint8_t Tins::IP::DEFAULT_TTL = 128;

Tins::IP::IP(const string &ip_dst, const string &ip_src, PDU *child) : PDU(IPPROTO_IP, child) {
    init_ip_fields();
    if(ip_dst.size())
        _ip.daddr = Utils::resolve_ip(ip_dst);
    if(ip_src.size())
        _ip.saddr = Utils::resolve_ip(ip_src);

}

Tins::IP::IP(uint32_t ip_dst, uint32_t ip_src, PDU *child) : PDU(IPPROTO_IP, child) {
    init_ip_fields();
    _ip.daddr = ip_dst;
    _ip.saddr = ip_src;
}

void Tins::IP::init_ip_fields() {
    memset(&_ip, 0, sizeof(iphdr));
    _ip.version = 4;
    _ip.ihl = sizeof(iphdr) / sizeof(uint32_t);
    _ip.ttl = DEFAULT_TTL;
    _options_size = 0;
}

/* Setters */

void Tins::IP::tos(uint8_t new_tos) {
    _ip.tos = new_tos;
}

void Tins::IP::tot_len(uint16_t new_tot_len) {
    _ip.tot_len = new_tot_len;
}

void Tins::IP::id(uint16_t new_id) {
    _ip.id = new_id;
}

void Tins::IP::frag_off(uint16_t new_frag_off) {
    _ip.frag_off = new_frag_off;
}

void Tins::IP::ttl(uint8_t new_ttl) {
    _ip.ttl = new_ttl;
}

void Tins::IP::protocol(uint8_t new_protocol) {
    _ip.protocol = new_protocol;
}

void Tins::IP::check(uint16_t new_check) {
    _ip.check = new_check;
}

void Tins::IP::source_address(const string &ip) {
    _ip.saddr = Utils::resolve_ip(ip);
}

void Tins::IP::source_address(uint32_t ip) {
    _ip.saddr = ip;
}

void Tins::IP::dest_address(const string &ip) {
    _ip.daddr = Utils::resolve_ip(ip);
}

void Tins::IP::dest_address(uint32_t ip) {
    _ip.daddr = ip;
}

void Tins::IP::set_option_eol() {
    this->set_option(0, IP::CONTROL, IP::IPOPT_END);
}

void Tins::IP::set_option_noop() {
    this->set_option(0, IP::CONTROL, IP::IPOPT_NOOP);
}

void Tins::IP::set_option_sec(uint8_t* data, uint32_t data_len) {
    assert(data_len == 10);
    this->set_option(1, IP::CONTROL, IP::IPOPT_SEC, data, data_len);
}

void Tins::IP::set_option(uint8_t copied,
                OptionClass op_class,
                OptionNumber number,
                uint8_t* data,
                uint32_t data_size) {
    IpOption option;
    option.type.copied = copied;
    option.type.op_class = op_class;
    option.type.number = number;
    uint8_t* buffer(0);
    if (data_size) {
        /* data must be a valid pointer */
        assert(data);
        buffer = new uint8_t[data_size];
        memcpy(buffer, data, data_size);
    }
    option.optional_data = buffer;
    option.optional_data_size = data_size;
    _ip_options.push_back(option);
    _options_size += 1 + ((buffer)? (data_size) : 0);
    uint8_t padding = _options_size & 3;
    _padded_options_size = padding? (_options_size - padding + 4) : _options_size;
}

uint8_t* Tins::IP::IpOption::write(uint8_t* buffer) {

    memcpy(buffer, &type, 1);
    buffer += 1;
    if (optional_data) {
        memcpy(buffer, optional_data, optional_data_size);
        buffer += optional_data_size;
    }
    return buffer;
}

/* Virtual method overriding. */

uint32_t Tins::IP::header_size() const {
    return sizeof(iphdr) + _padded_options_size;

}

bool Tins::IP::send(PacketSender* sender) {
    struct sockaddr_in link_addr;
    link_addr.sin_family = AF_INET;
    link_addr.sin_port = 0;
    link_addr.sin_addr.s_addr = _ip.daddr;

    return sender->send_l3(this, (const struct sockaddr*)&link_addr, sizeof(link_addr));
}

void Tins::IP::write_serialization(uint8_t *buffer, uint32_t total_sz) {
    uint32_t my_sz = header_size();
    uint32_t new_flag;
    assert(total_sz >= my_sz);
    if(inner_pdu()) {
        new_flag = inner_pdu()->flag();
        if(new_flag == IPPROTO_IP)
            new_flag = IPPROTO_IPIP;
    }
    else
        new_flag = IPPROTO_IP;
    flag(new_flag);
    _ip.protocol = new_flag;
    _ip.tot_len = total_sz;
    _ip.ihl = my_sz / sizeof(uint32_t);
    memcpy(buffer, &_ip, sizeof(iphdr));

    /* IP Options here... */
    buffer += sizeof(iphdr);
    for (uint32_t i = 0; i < _ip_options.size(); ++i)
        buffer = _ip_options[i].write(buffer);
}
