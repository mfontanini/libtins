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

#include <stdexcept>
#include <cstring>
#ifdef TINS_DEBUG
#include <cassert>
#endif
#include <algorithm>
#ifndef WIN32
    #include <netdb.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock2.h>
#endif
#include "ip.h"
#include "rawpdu.h"
#include "utils.h"
#include "packet_sender.h"
#include "constants.h"
#include "network_interface.h"
#include "exceptions.h"
#include "pdu_allocator.h"

using std::list;

namespace Tins {

const uint8_t IP::DEFAULT_TTL = 128;

IP::IP(address_type ip_dst, address_type ip_src) 
{
    init_ip_fields();
    this->dst_addr(ip_dst);
    this->src_addr(ip_src); 
}

IP::IP(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(iphdr))
        throw malformed_packet();
    std::memcpy(&_ip, buffer, sizeof(iphdr));

    /* Options... */
    /* Establish beginning and ending of the options */
    const uint8_t* ptr_buffer = buffer + sizeof(iphdr);
    if(total_sz < head_len() * sizeof(uint32_t))
        throw malformed_packet();
    if(head_len() * sizeof(uint32_t) < sizeof(iphdr))
        throw malformed_packet();
    buffer += head_len() * sizeof(uint32_t);
    
    _options_size = 0;
    //_padded_options_size = head_len() * sizeof(uint32_t) - sizeof(iphdr);
    /* While the end of the options is not reached read an option */
    while (ptr_buffer < buffer && (*ptr_buffer != 0)) {
        //ip_option opt_to_add;
        option_identifier opt_type;
        memcpy(&opt_type, ptr_buffer, sizeof(uint8_t));
        ptr_buffer++;
        if(opt_type.number > NOOP) {
            /* Multibyte options with length as second byte */
            if(ptr_buffer == buffer || *ptr_buffer == 0)
                throw malformed_packet();
                
            const uint8_t data_size = *ptr_buffer - 2;
            if(data_size > 0) {
                ptr_buffer++;
                if(buffer - ptr_buffer < data_size)
                    throw malformed_packet();
                _ip_options.push_back(option(opt_type, ptr_buffer, ptr_buffer + data_size));
            }
            else
                _ip_options.push_back(option(opt_type));
            
            ptr_buffer += _ip_options.back().data_size() + 1;
            _options_size += _ip_options.back().data_size() + 2;
        }
        else {
            _ip_options.push_back(option(opt_type));
            _options_size++;
        }
    }
    uint8_t padding = _options_size % 4;
    _padded_options_size = padding ? (_options_size - padding + 4) : _options_size;
    // Don't avoid consuming more than we should if tot_len is 0,
    // since this is the case when using TCP segmentation offload
    if (tot_len() != 0) 
        total_sz = std::min(total_sz, (uint32_t)tot_len());
    if (total_sz < head_len() * sizeof(uint32_t))
        throw malformed_packet();
    total_sz -= head_len() * sizeof(uint32_t);
    if (total_sz) {
        // Don't try to decode it if it's fragmented
        if(!is_fragmented()) {
            inner_pdu(
                Internals::pdu_from_flag(
                    static_cast<Constants::IP::e>(_ip.protocol),
                    buffer, 
                    total_sz,
                    false
                )
            );
            if(!inner_pdu()) {
                inner_pdu(
                    Internals::allocate<IP>(
                        _ip.protocol,
                        buffer, 
                        total_sz
                    )
                );
                if(!inner_pdu())
                    inner_pdu(new RawPDU(buffer, total_sz));
            }
        }
        else {
            // It's fragmented, just use RawPDU
            inner_pdu(new RawPDU(buffer, total_sz));
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

bool IP::is_fragmented() const {
    // It's 0 if offset == 0 && more_frag == 0
    // It's 0x4000 if dont_fragment = 1
    return frag_off() != 0 && frag_off() != 0x4000;
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

void IP::checksum(uint16_t new_check) {
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
        option(
            130,
            sizeof(array),
            array
        )
    );
}

void IP::stream_identifier(uint16_t stream_id) {
    stream_id = Endian::host_to_be(stream_id);
        add_option(
        option(
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
        option(
            id,
            opt_data.size(),
            &opt_data[0]
        )
    );
}

IP::generic_route_option_type IP::search_route_option(option_identifier id) const {
    const option *opt = search_option(id);
    if(!opt)
        throw option_not_found();
    return opt->to<generic_route_option_type>();
}

IP::security_type IP::security() const {
    const option *opt = search_option(130);
    if(!opt)
        throw option_not_found();
    return opt->to<security_type>();
}

uint16_t IP::stream_identifier() const {
    const option *opt = search_option(136);
    if(!opt)
        throw option_not_found();
    return opt->to<uint16_t>();
}

void IP::add_option(const option &opt) {
    internal_add_option(opt);
    _ip_options.push_back(opt);
}

void IP::internal_add_option(const option &opt) {
    _options_size += 1 + opt.data_size();
    uint8_t padding = _options_size % 4;
    _padded_options_size = padding ? (_options_size - padding + 4) : _options_size;
}

const IP::option *IP::search_option(option_identifier id) const {
    for(options_type::const_iterator it = _ip_options.begin(); it != _ip_options.end(); ++it) {
        if(it->option() == id)
            return &(*it);
    }
    return 0;
}

uint8_t* IP::write_option(const option &opt, uint8_t* buffer) {
    option_identifier opt_type = opt.option();
    memcpy(buffer, &opt_type, 1);
    if(*buffer <= 1)
        return ++buffer;
    buffer++;
    *buffer = opt.length_field();
    if(opt.data_size() == opt.length_field())
        *buffer += 2;
    buffer++;
    return std::copy(opt.data_ptr(), opt.data_ptr() + opt.data_size(), buffer);
}

/* Virtual method overriding. */

uint32_t IP::header_size() const {
    return sizeof(iphdr) + _padded_options_size;
}

PacketSender::SocketType pdu_type_to_sender_type(PDU::PDUType type) {
    switch(type) {
        case PDU::TCP:
            return PacketSender::IP_TCP_SOCKET;
        case PDU::UDP:
            return PacketSender::IP_UDP_SOCKET;
        case PDU::ICMP:
            return PacketSender::ICMP_SOCKET;
        default:
            return PacketSender::IP_RAW_SOCKET;
    }
}

void IP::send(PacketSender& sender, const NetworkInterface &) {
    sockaddr_in link_addr;
    PacketSender::SocketType type = PacketSender::IP_RAW_SOCKET;
    link_addr.sin_family = AF_INET;
    link_addr.sin_port = 0;
    link_addr.sin_addr.s_addr = _ip.daddr;
    if(inner_pdu())
        type = pdu_type_to_sender_type(inner_pdu()->pdu_type());

    sender.send_l3(*this, (struct sockaddr*)&link_addr, sizeof(link_addr), type);
}

PDU *IP::recv_response(PacketSender &sender, const NetworkInterface &) {
    sockaddr_in link_addr;
    PacketSender::SocketType type = PacketSender::IP_RAW_SOCKET;
    std::memset(&link_addr, 0, sizeof(link_addr));
    if(inner_pdu())
        type = pdu_type_to_sender_type(inner_pdu()->pdu_type());

    return sender.recv_l3(*this, 0, sizeof(link_addr), type);
}

void IP::prepare_for_serialize(const PDU *parent) {
    if(!parent && _ip.saddr == 0) {
        NetworkInterface iface(dst_addr());
        src_addr(iface.addresses().ip_addr);
    }
}

void IP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU* parent) {
    uint32_t my_sz = header_size();
    #ifdef TINS_DEBUG
    assert(total_sz >= my_sz);
    #endif
    checksum(0);
    if(inner_pdu()) {
        uint32_t new_flag = Internals::pdu_flag_to_ip_type(inner_pdu()->pdu_type());
        if(new_flag == 0xff && Internals::pdu_type_registered<IP>(inner_pdu()->pdu_type())) {
            new_flag = static_cast<Constants::IP::e>(
                Internals::pdu_type_to_id<IP>(inner_pdu()->pdu_type())
            );
        }
        if(!is_fragmented() || new_flag != 0xff)
            protocol(new_flag);
    }
    
    #if __FreeBSD__ || defined(__FreeBSD_kernel__) || __APPLE__
        if(!parent)
            total_sz = Endian::host_to_be<uint16_t>(total_sz);
    #endif
    tot_len(total_sz);
    head_len(my_sz / sizeof(uint32_t));

    memcpy(buffer, &_ip, sizeof(_ip));

    uint8_t* ptr_buffer = buffer + sizeof(_ip);
    for(options_type::const_iterator it = _ip_options.begin(); it != _ip_options.end(); ++it) {
        ptr_buffer = write_option(*it, ptr_buffer);
    }
    memset(buffer + sizeof(_ip) + _options_size, 0, _padded_options_size - _options_size);

    if(parent) {
        uint32_t check = Utils::do_checksum(buffer, buffer + sizeof(_ip) + _padded_options_size);
        while (check >> 16)
            check = (check & 0xffff) + (check >> 16);
        checksum(~check);
        ((iphdr*)buffer)->check = _ip.check;
    }
}

bool IP::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(total_sz < sizeof(iphdr))
        return false;
    const iphdr *ip_ptr = (const iphdr*)ptr;
    // dest unreachable?
    if(ip_ptr->protocol == Constants::IP::PROTO_ICMP) {
        const uint8_t *pkt_ptr = ptr + sizeof(iphdr);
        uint32_t pkt_sz = total_sz - sizeof(iphdr);
        // It's an ICMP dest unreachable
        if(pkt_sz > 4 && pkt_ptr[0] == 3) {
            pkt_ptr += 4;
            pkt_sz -= 4;
            // If our IP header is in the ICMP payload, then it's the same packet.
            // This keeps in mind checksum and IP identifier, so I guess it's enough.
            if(pkt_sz >= sizeof(iphdr) && std::memcmp(&_ip, pkt_ptr, sizeof(iphdr))) 
                return true;
        }
    }
    // checks for broadcast addr
    if((_ip.saddr == ip_ptr->daddr && (_ip.daddr == ip_ptr->saddr || dst_addr().is_broadcast())) ||
        (dst_addr().is_broadcast() && _ip.saddr == 0)) {
        uint32_t sz = std::min<uint32_t>(header_size(), total_sz);
        return inner_pdu() ? inner_pdu()->matches_response(ptr + sz, total_sz - sz) : true;
    }
    return false;
}

// Option static constructors from options

IP::security_type IP::security_type::from_option(const option &opt) 
{
    if(opt.data_size() != 9)
        throw malformed_option();
    security_type output;

    memcpy(&output.security, opt.data_ptr(), sizeof(uint16_t));
    output.security = Endian::be_to_host(output.security);
    memcpy(&output.compartments, opt.data_ptr() + sizeof(uint16_t), sizeof(uint16_t));
    output.compartments = Endian::be_to_host(output.compartments);
    memcpy(&output.handling_restrictions, opt.data_ptr() + 2 * sizeof(uint16_t), sizeof(uint16_t));
    output.handling_restrictions = Endian::be_to_host(output.handling_restrictions);
    uint32_t tcc = opt.data_ptr()[6];
    tcc = (tcc << 8) | opt.data_ptr()[7];
    tcc = (tcc << 8) | opt.data_ptr()[8];
    output.transmission_control = tcc;
    return output;
}

IP::generic_route_option_type IP::generic_route_option_type::from_option(
  const option &opt) 
{
    if(opt.data_size() < 1 + sizeof(uint32_t) || ((opt.data_size() - 1) % sizeof(uint32_t)) != 0)
        throw malformed_option();
    generic_route_option_type output;
    output.pointer = *opt.data_ptr();
    const uint8_t *route = opt.data_ptr() + 1;
    const uint8_t *end = route + opt.data_size() - 1;

    uint32_t uint32_t_buffer;
    while(route < end) {
        memcpy(&uint32_t_buffer, route, sizeof(uint32_t));
        output.routes.push_back(address_type(uint32_t_buffer));
        route += sizeof(uint32_t);
    }
    return output;
}
}
