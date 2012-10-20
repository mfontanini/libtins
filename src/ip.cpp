/*
 * Copyright (c) 2012, Nasel
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
#include <cstring>
#include <cassert>
#include <algorithm>
#ifndef WIN32
    #include <netdb.h>
    #include <sys/socket.h>
#else
    #include <winsock2.h>
#endif
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "rawpdu.h"
#include "utils.h"
#include "packet_sender.h"
#include "constants.h"

using std::list;

namespace Tins {

const uint8_t IP::DEFAULT_TTL = 128;

IP::IP(address_type ip_dst, address_type ip_src, PDU *child) 
: PDU(child) 
{
    init_ip_fields();
    this->dst_addr(ip_dst);
    this->src_addr(ip_src); 
}

IP::IP(const uint8_t *buffer, uint32_t total_sz) 
{
    const char *msg = "Not enough size for an IP header in the buffer.";
    if(total_sz < sizeof(iphdr))
        throw std::runtime_error(msg);
    std::memcpy(&_ip, buffer, sizeof(iphdr));

    /* Options... */
    /* Establish beginning and ending of the options */
    const uint8_t* ptr_buffer = buffer + sizeof(iphdr);
    if(total_sz < head_len() * sizeof(uint32_t))
        throw std::runtime_error(msg);
    if(head_len() * sizeof(uint32_t) < sizeof(iphdr))
        throw std::runtime_error("Malformed head len field");
    buffer += head_len() * sizeof(uint32_t);
    
    _options_size = 0;
    //_padded_options_size = head_len() * sizeof(uint32_t) - sizeof(iphdr);
    /* While the end of the options is not reached read an option */
    while (ptr_buffer < buffer && (*ptr_buffer != 0)) {
        //ip_option opt_to_add;
        option_identifier opt_type;
        memcpy(&opt_type, ptr_buffer, sizeof(uint8_t));
        ptr_buffer++;
        switch (opt_type.number) {
            /* Multibyte options with length as second byte */
            case SEC:
            case LSSR:
            case TIMESTAMP:
            case EXTSEC:
            case RR:
            case SID:
            case SSRR:
            case MTUPROBE:
            case MTUREPLY:
            case EIP:
            case TR:
            case ADDEXT:
            case RTRALT:
            case SDB:
            case DPS:
            case UMP:
            case QS:
                if(ptr_buffer == buffer || *ptr_buffer == 0)
                    throw std::runtime_error(msg);
                    
                {
                    const uint8_t data_size = *ptr_buffer - 2;
                    if(data_size > 0) {
                        ptr_buffer++;
                        if(buffer - ptr_buffer < data_size)
                            throw std::runtime_error(msg);
                        _ip_options.push_back(ip_option(opt_type, ptr_buffer, ptr_buffer + data_size));
                    }
                    else
                        _ip_options.push_back(ip_option(opt_type));
                }
                
                ptr_buffer += _ip_options.back().data_size() + 1;
                break;
            default:
                _ip_options.push_back(ip_option(opt_type));
                break;
        }
        _options_size += _ip_options.back().data_size() + 2;
    }
    uint8_t padding = _options_size % 4;
    _padded_options_size = padding ? (_options_size - padding + 4) : _options_size;
    // check this line PLX
    total_sz -= head_len() * sizeof(uint32_t);
    if (total_sz) {
        switch(_ip.protocol) {
            case Constants::IP::PROTO_TCP:
                inner_pdu(new Tins::TCP(buffer, total_sz));
                break;
            case Constants::IP::PROTO_UDP:
                inner_pdu(new Tins::UDP(buffer, total_sz));
                break;
            case Constants::IP::PROTO_ICMP:
                inner_pdu(new Tins::ICMP(buffer, total_sz));
                break;
            default:
                inner_pdu(new Tins::RawPDU(buffer, total_sz));
                break;
        }
    }
}

void IP::init_ip_fields() {
    memset(&_ip, 0, sizeof(iphdr));
    _ip.version = 4;
    ttl(DEFAULT_TTL);
    id(1);
    _options_size = 0;
    _padded_options_size = 0;
}

/* Setters */

void IP::tos(uint8_t new_tos) {
    _ip.tos = new_tos;
}

void IP::tot_len(uint16_t new_tot_len) {
    _ip.tot_len = Endian::host_to_be(new_tot_len);
}

void IP::id(uint16_t new_id) {
    _ip.id = Endian::host_to_be(new_id);
}

void IP::frag_off(uint16_t new_frag_off) {
    _ip.frag_off = Endian::host_to_be(new_frag_off);
}

void IP::ttl(uint8_t new_ttl) {
    _ip.ttl = new_ttl;
}

void IP::protocol(uint8_t new_protocol) {
    _ip.protocol = new_protocol;
}

void IP::check(uint16_t new_check) {
    _ip.check = Endian::host_to_be(new_check);
}


void IP::src_addr(address_type ip) {
    _ip.saddr = ip;
}


void IP::dst_addr(address_type ip) {
    _ip.daddr = ip;
}

void IP::head_len(small_uint<4> new_head_len) {
    _ip.ihl = new_head_len;
}

void IP::version(small_uint<4> ver) {
    _ip.version = ver;
}

void IP::eol() {
    add_option(option_identifier(IP::END, IP::CONTROL, 0));
}

void IP::noop() {
    add_option(option_identifier(IP::NOOP, IP::CONTROL, 0));
}

void IP::security(const security_type &data) {
    uint8_t array[9];
    uint16_t *ptr = reinterpret_cast<uint16_t*>(array);
    uint32_t value = data.transmission_control;
    *ptr++ = Endian::host_to_be(data.security);
    *ptr++ = Endian::host_to_be(data.compartments);
    *ptr++ = Endian::host_to_be(data.handling_restrictions);
    array[8] = (value & 0xff);
    array[7] = ((value >> 8) & 0xff);
    array[6] = ((value >> 16) & 0xff);
    
    add_option(
        ip_option(
            130,
            sizeof(array),
            array
        )
    );
}

void IP::stream_identifier(uint16_t stream_id) {
    stream_id = Endian::host_to_be(stream_id);
        add_option(
        ip_option(
            136,
            sizeof(uint16_t),
            (const uint8_t*)&stream_id
        )
    );
}

void IP::add_route_option(option_identifier id, const generic_route_option_type &data) {
    std::vector<uint8_t> opt_data(1 + sizeof(uint32_t) * data.routes.size());
    opt_data[0] = data.pointer;
    for(size_t i(0); i < data.routes.size(); ++i) {
        uint32_t ip = data.routes[i];
        #if TINS_IS_BIG_ENDIAN
            ip = Endian::change_endian(ip);
        #endif
        opt_data[1 + i * 4] = ip & 0xff;
        opt_data[1 + i * 4 + 1] = (ip >> 8) & 0xff;
        opt_data[1 + i * 4 + 2] = (ip >> 16) & 0xff;
        opt_data[1 + i * 4 + 3] = (ip >> 24) & 0xff;
    }
    add_option(
        ip_option(
            id,
            opt_data.size(),
            &opt_data[0]
        )
    );
}

IP::generic_route_option_type IP::search_route_option(option_identifier id) const {
    const ip_option *option = search_option(id);
    if(!option || option->data_size() < 1 + sizeof(uint32_t) || 
      ((option->data_size() - 1) % sizeof(uint32_t)) != 0)
        throw option_not_found();
    generic_route_option_type output;
    output.pointer = *option->data_ptr();
    const uint32_t *route = (const uint32_t*)(option->data_ptr() + 1),
                    *end = route + (option->data_size() - 1) / sizeof(uint32_t);
    while(route < end)
        output.routes.push_back(address_type(*route++));
    return output;
}

IP::security_type IP::security() const {
    const ip_option *option = search_option(130);
    if(!option || option->data_size() < 9)
        throw option_not_found();
    security_type output;
    const uint16_t *ptr = reinterpret_cast<const uint16_t*>(option->data_ptr());
    output.security = Endian::be_to_host(*ptr++);
    output.compartments = Endian::be_to_host(*ptr++);
    output.handling_restrictions = Endian::be_to_host(*ptr++);
    uint32_t tcc = option->data_ptr()[6];
    tcc = (tcc << 8) | option->data_ptr()[7];
    tcc = (tcc << 8) | option->data_ptr()[8];
    output.transmission_control = tcc;
    return output;
}

uint16_t IP::stream_identifier() const {
    const ip_option *option = search_option(136);
    if(!option || option->data_size() != sizeof(uint16_t))
        throw option_not_found();
    return Endian::be_to_host(*(const uint16_t*)option->data_ptr());
}

void IP::add_option(const ip_option &option) {
    _ip_options.push_back(option);
    _options_size += 1 + option.data_size();
    uint8_t padding = _options_size % 4;
    _padded_options_size = padding ? (_options_size - padding + 4) : _options_size;
}

const IP::ip_option *IP::search_option(option_identifier id) const {
    for(std::list<ip_option>::const_iterator it = _ip_options.begin(); it != _ip_options.end(); ++it) {
        if(it->option() == id)
            return &(*it);
    }
    return 0;
}

uint8_t* IP::write_option(const ip_option &opt, uint8_t* buffer) {
    option_identifier opt_type = opt.option();
    memcpy(buffer, &opt_type, 1);
    buffer++;
    *(buffer++) = opt.data_size() + 2;
    std::copy(opt.data_ptr(), opt.data_ptr() + opt.data_size(), buffer);
    buffer += opt.data_size();
    return buffer;
}

/* Virtual method overriding. */

uint32_t IP::header_size() const {
    return sizeof(iphdr) + _padded_options_size;
}

void IP::send(PacketSender& sender) {
    struct sockaddr_in link_addr;
    PacketSender::SocketType type = PacketSender::IP_SOCKET;
    link_addr.sin_family = AF_INET;
    link_addr.sin_port = 0;
    link_addr.sin_addr.s_addr = _ip.daddr;
    if(inner_pdu() && inner_pdu()->pdu_type() == PDU::ICMP)
        type = PacketSender::ICMP_SOCKET;

    sender.send_l3(*this, (struct sockaddr*)&link_addr, sizeof(link_addr), type);
}

PDU *IP::recv_response(PacketSender &sender) {
    struct sockaddr_in link_addr;
    PacketSender::SocketType type = PacketSender::IP_SOCKET;
    link_addr.sin_family = AF_INET;
    link_addr.sin_port = 0;
    link_addr.sin_addr.s_addr = _ip.daddr;
    if(inner_pdu() && inner_pdu()->pdu_type() == PDU::ICMP)
        type = PacketSender::ICMP_SOCKET;

    return sender.recv_l3(*this, (struct sockaddr*)&link_addr, sizeof(link_addr), type);
}

void IP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU* parent) {
    uint32_t my_sz = header_size();
    assert(total_sz >= my_sz);
    if(inner_pdu()) {
        uint32_t new_flag;
        switch(inner_pdu()->pdu_type()) {
            case PDU::IP:
                new_flag = Constants::IP::PROTO_IPIP;
                break;
            case PDU::TCP:
                new_flag = Constants::IP::PROTO_TCP;
                break;
            case PDU::UDP:
                new_flag = Constants::IP::PROTO_UDP;
                break;
            case PDU::ICMP:
                new_flag = Constants::IP::PROTO_ICMP;
                break;
            default:
                // check for other protos
                new_flag = 0xff;
        };
        protocol(new_flag);
        //flag(new_flag);
    }
    tot_len(total_sz);
    head_len(my_sz / sizeof(uint32_t));

    memcpy(buffer, &_ip, sizeof(_ip));

    uint8_t* ptr_buffer = buffer + sizeof(_ip);
    for(list<ip_option>::iterator it = _ip_options.begin(); it != _ip_options.end(); ++it)
        ptr_buffer = write_option(*it, ptr_buffer);
    memset(buffer + sizeof(_ip) + _options_size, 0, _padded_options_size - _options_size);

    if(parent && !_ip.check) {
        uint32_t checksum = Utils::do_checksum(buffer, buffer + sizeof(_ip) + _padded_options_size);
        while (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16);
        ((iphdr*)buffer)->check = Endian::host_to_be<uint16_t>(~checksum);
        this->check(0);
    }
}

bool IP::matches_response(uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(iphdr))
        return false;
    iphdr *ip_ptr = (iphdr*)ptr;
    if(_ip.daddr == ip_ptr->saddr && _ip.saddr == ip_ptr->daddr) {
        uint32_t sz = _ip.ihl * sizeof(uint32_t);
        return inner_pdu() ? inner_pdu()->matches_response(ptr + sz, total_sz - sz) : true;
    }
    return false;
}

PDU *IP::clone_packet(const uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(iphdr))
        return 0;
    const iphdr *ip_ptr = (iphdr*)ptr;
    uint32_t sz = ip_ptr->ihl * sizeof(uint32_t);
    if(total_sz < sz)
        return 0;
    PDU *child = 0, *cloned;
    if(total_sz > sz) {
        if((child = PDU::clone_inner_pdu(ptr + sizeof(_ip), total_sz - sizeof(_ip))) == 0)
            return 0;
    }
    cloned = new IP(ptr, std::min(total_sz, (uint32_t)(Endian::be_to_host(ip_ptr->tot_len) * sizeof(uint32_t))));
    cloned->inner_pdu(child);
    return cloned;
}
}
