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
#ifndef WIN32
    #include <netinet/in.h>
#endif
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "rawpdu.h"
#include "utils.h"


using namespace std;

const uint8_t Tins::IP::DEFAULT_TTL = 128;

Tins::IP::IP(const string &ip_dst, const string &ip_src, PDU *child) : PDU(IPPROTO_IP, child) {
    init_ip_fields();
    if(ip_dst.size())
        _ip.daddr = Utils::resolve_ip(ip_dst);
    if(ip_src.size())
        _ip.saddr = Utils::resolve_ip(ip_src);

}

Tins::IP::IP(const uint8_t *buffer, uint32_t total_sz) : PDU(IPPROTO_IP) {
    if(total_sz < sizeof(iphdr))
        throw std::runtime_error("Not enough size for an IP header in the buffer.");
    std::memcpy(&_ip, buffer, sizeof(iphdr));

    /* Options... */
    /* Establish beginning and ending of the options */
    const uint8_t* ptr_buffer = buffer + sizeof(iphdr);
    buffer += head_len() * sizeof(uint32_t);
    this->_options_size = 0;
    this->_padded_options_size = head_len() * sizeof(uint32_t) - sizeof(iphdr);
    /* While the end of the options is not reached read an option */
    while (ptr_buffer < buffer && (*ptr_buffer != 0)) {
        IpOption opt_to_add;
        opt_to_add.optional_data = NULL;
        opt_to_add.optional_data_size = 0;
        memcpy(&opt_to_add.type, ptr_buffer, 1);
        ptr_buffer++;
        switch (opt_to_add.type.number) {
            /* Multibyte options with length as second byte */
            case IPOPT_SEC:
            case IPOPT_LSSR:
            case IPOPT_TIMESTAMP:
            case IPOPT_EXTSEC:
            case IPOPT_RR:
            case IPOPT_SID:
            case IPOPT_SSRR:
            case IPOPT_MTUPROBE:
            case IPOPT_MTUREPLY:
            case IPOPT_EIP:
            case IPOPT_TR:
            case IPOPT_ADDEXT:
            case IPOPT_RTRALT:
            case IPOPT_SDB:
            case IPOPT_DPS:
            case IPOPT_UMP:
            case IPOPT_QS:
                opt_to_add.optional_data_size = *ptr_buffer - 1;
                opt_to_add.optional_data = new uint8_t[opt_to_add.optional_data_size];
                memcpy(opt_to_add.optional_data, ptr_buffer, opt_to_add.optional_data_size);
                ptr_buffer += opt_to_add.optional_data_size;
        }
        this->_ip_options.push_back(opt_to_add);
        this->_options_size += 1 + opt_to_add.optional_data_size;
    }

    total_sz -= head_len() * sizeof(uint32_t);
    if (total_sz == 0)
        return;
    switch(_ip.protocol) {
        case IPPROTO_TCP:
            inner_pdu(new Tins::TCP(buffer, total_sz));
            break;
        case IPPROTO_UDP:
            inner_pdu(new Tins::UDP(buffer, total_sz));
            break;
        case IPPROTO_ICMP:
            inner_pdu(new Tins::ICMP(buffer, total_sz));
            break;
        default:
            inner_pdu(new Tins::RawPDU(buffer, total_sz));
            break;
    }
}

Tins::IP::IP(const iphdr *ptr) : PDU(IPPROTO_IP) {
    std::memcpy(&_ip, ptr, sizeof(iphdr));
    /* Options... */
}

Tins::IP::IP(uint32_t ip_dst, uint32_t ip_src, PDU *child) : PDU(IPPROTO_IP, child) {
    init_ip_fields();
    _ip.daddr = ip_dst;
    _ip.saddr = ip_src;
}

Tins::IP::~IP() {
    for (vector<IpOption>::iterator it = this->_ip_options.begin(); it != this->_ip_options.end(); it++) {
        if (it->optional_data)
            delete[] it->optional_data;
    }
}

void Tins::IP::init_ip_fields() {
    memset(&_ip, 0, sizeof(iphdr));
    this->_ip.version = 4;
    this->ttl(DEFAULT_TTL);
    this->id(1);
    this->_options_size = 0;
    this->_padded_options_size = 0;
}

/* Setters */

void Tins::IP::tos(uint8_t new_tos) {
    _ip.tos = new_tos;
}

void Tins::IP::tot_len(uint16_t new_tot_len) {
    _ip.tot_len = Utils::net_to_host_s(new_tot_len);
}

void Tins::IP::id(uint16_t new_id) {
    _ip.id = Utils::net_to_host_s(new_id);
}

void Tins::IP::frag_off(uint16_t new_frag_off) {
    _ip.frag_off = Utils::net_to_host_s(new_frag_off);
}

void Tins::IP::ttl(uint8_t new_ttl) {
    _ip.ttl = new_ttl;
}

void Tins::IP::protocol(uint8_t new_protocol) {
    _ip.protocol = new_protocol;
}

void Tins::IP::check(uint16_t new_check) {
    _ip.check = Utils::net_to_host_s(new_check);
}

void Tins::IP::src_addr(const string &ip) {
    _ip.saddr = Utils::resolve_ip(ip);
}

void Tins::IP::src_addr(uint32_t ip) {
    _ip.saddr = ip;
}

void Tins::IP::dst_addr(const string &ip) {
    _ip.daddr = Utils::resolve_ip(ip);
}

void Tins::IP::dst_addr(uint32_t ip) {
    _ip.daddr = ip;
}

void Tins::IP::head_len(uint8_t new_head_len) {
    this->_ip.ihl = new_head_len;
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
    PacketSender::SocketType type = PacketSender::IP_SOCKET;
    link_addr.sin_family = AF_INET;
    link_addr.sin_port = 0;
    link_addr.sin_addr.s_addr = _ip.daddr;
    if(inner_pdu() && inner_pdu()->flag() == IPPROTO_ICMP)
        type = PacketSender::ICMP_SOCKET;

    return sender->send_l3(this, (struct sockaddr*)&link_addr, sizeof(link_addr), type);
}

Tins::PDU *Tins::IP::recv_response(PacketSender *sender) {
    struct sockaddr_in link_addr;
    PacketSender::SocketType type = PacketSender::IP_SOCKET;
    link_addr.sin_family = AF_INET;
    link_addr.sin_port = 0;
    link_addr.sin_addr.s_addr = _ip.daddr;
    if(inner_pdu() && inner_pdu()->flag() == IPPROTO_ICMP)
        type = PacketSender::ICMP_SOCKET;

    return sender->recv_l3(this, (struct sockaddr*)&link_addr, sizeof(link_addr), type);
}

void Tins::IP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU* parent) {
    uint32_t my_sz = header_size();
    assert(total_sz >= my_sz);
    if(inner_pdu()) {
        uint32_t new_flag;
        new_flag = inner_pdu()->flag();
        if(new_flag == IPPROTO_IP)
            new_flag = IPPROTO_IPIP;

        this->protocol(new_flag);
        this->flag(new_flag);
    }
    this->tot_len(total_sz);
    this->head_len (my_sz / sizeof(uint32_t));

    memcpy(buffer, &_ip, sizeof(iphdr));

    uint8_t* ptr_buffer = buffer + sizeof(iphdr);
    for (uint32_t i = 0; i < _ip_options.size(); ++i)
        ptr_buffer = _ip_options[i].write(ptr_buffer);

    memset(buffer + sizeof(iphdr) + this->_options_size, 0, this->_padded_options_size - this->_options_size);

    if (parent && !_ip.check) {
        uint32_t checksum = PDU::do_checksum(buffer, buffer + sizeof(iphdr) + _padded_options_size);
        while (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16);
        ((iphdr*)buffer)->check = Utils::net_to_host_s(~checksum);
        this->check(0);
    }


}

bool Tins::IP::matches_response(uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(iphdr))
        return false;
    iphdr *ip_ptr = (iphdr*)ptr;
    if(_ip.daddr == ip_ptr->saddr && _ip.saddr == ip_ptr->daddr) {
        uint32_t sz = _ip.ihl * sizeof(uint32_t);
        return inner_pdu() ? inner_pdu()->matches_response(ptr + sz, total_sz - sz) : true;
    }
    return false;
}

Tins::PDU *Tins::IP::clone_packet(const uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(iphdr))
        return 0;
    const iphdr *ip_ptr = (iphdr*)ptr;
    uint32_t sz = ip_ptr->ihl * sizeof(uint32_t);
    if(total_sz < sz)
        return 0;
    PDU *child = 0, *cloned;
    if(total_sz > sz) {
        if(inner_pdu()) {
            child = inner_pdu()->clone_packet(ptr + sz, total_sz - sz);
            if(!child)
                return 0;
        }
        else
            child = new RawPDU(ptr + sz, total_sz - sz);
    }
    cloned = new IP(ip_ptr);
    cloned->inner_pdu(child);
    return cloned;
}
