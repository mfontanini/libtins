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

#include <cstring>
#include <cassert>
#include "tcp.h"
#include "ip.h"
#include "ipv6.h"
#include "constants.h"
#include "rawpdu.h"
#include "utils.h"

namespace Tins {

const uint16_t TCP::DEFAULT_WINDOW = 32678;

TCP::TCP(uint16_t dport, uint16_t sport) 
: _options_size(0), _total_options_size(0) 
{
    std::memset(&_tcp, 0, sizeof(tcphdr));
    this->dport(dport);
    this->sport(sport);
    data_offset(sizeof(tcphdr) / sizeof(uint32_t));
    window(DEFAULT_WINDOW);
}

TCP::TCP(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(tcphdr))
        throw std::runtime_error("Not enough size for an TCP header in the buffer.");
    std::memcpy(&_tcp, buffer, sizeof(tcphdr));
    buffer += sizeof(tcphdr);
    total_sz -= sizeof(tcphdr);
    
    _total_options_size = 0;
    _options_size = 0;
    
    uint32_t index = 0, header_end = (data_offset() * sizeof(uint32_t)) - sizeof(tcphdr);
    if(total_sz >= header_end) {
        uint8_t args[2] = {0};
        while(index < header_end) {
            for(unsigned i(0); i < 2; ++i) {
                if(index == header_end)
                    throw std::runtime_error("Not enough size for a TCP header in the buffer.");
                args[i] = buffer[index++];
                // NOP and EOL contain no length field
                if(args[0] == NOP || args[0] == EOL)
                    break;
            }
            // We don't want to store NOPs and EOLs
            if(args[0] != NOP && args[0] != EOL)  {
                // Not enough size for this option
                args[1] -= (sizeof(uint8_t) << 1);
                if(header_end - index < args[1])
                    throw std::runtime_error("Not enough size for a TCP header in the buffer.");                        
                if(args[1])
                    add_option(option((OptionTypes)args[0], buffer + index, buffer + index + args[1]));
                else
                    add_option(option((OptionTypes)args[0], args[1], 0));
                index += args[1];
            }
            else
                add_option(option((OptionTypes)args[0], 0));
        }
        buffer += index;
        total_sz -= index;
    }
    if(total_sz)
        inner_pdu(new RawPDU(buffer, total_sz));
}

void TCP::dport(uint16_t new_dport) {
    _tcp.dport = Endian::host_to_be(new_dport);
}

void TCP::sport(uint16_t new_sport) {
    _tcp.sport = Endian::host_to_be(new_sport);
}

void TCP::seq(uint32_t new_seq) {
    _tcp.seq = Endian::host_to_be(new_seq);
}

void TCP::ack_seq(uint32_t new_ack_seq) {
    _tcp.ack_seq = Endian::host_to_be(new_ack_seq);
}

void TCP::window(uint16_t new_window) {
    _tcp.window = Endian::host_to_be(new_window);
}

void TCP::check(uint16_t new_check) {
    _tcp.check = Endian::host_to_be(new_check);
}

void TCP::urg_ptr(uint16_t new_urg_ptr) {
    _tcp.urg_ptr = Endian::host_to_be(new_urg_ptr);
}

void TCP::data_offset(small_uint<4> new_doff) {
    this->_tcp.doff = new_doff;
}

void TCP::mss(uint16_t value) {
    value = Endian::host_to_be(value);
    add_option(option(MSS, 2, (uint8_t*)&value));
}

uint16_t TCP::mss() const {
    return Endian::host_to_be(generic_search<uint16_t>(MSS));
}

void TCP::winscale(uint8_t value) {
    add_option(option(WSCALE, 1, &value));
}

uint8_t TCP::winscale() const {
    return generic_search<uint8_t>(WSCALE);
}

void TCP::sack_permitted() {
    add_option(option(SACK_OK, 0));
}

bool TCP::has_sack_permitted() const {
    return bool(search_option(SACK_OK));
}

void TCP::sack(const sack_type &edges) {
    uint32_t *value = 0;
    if(edges.size()) {
        value = new uint32_t[edges.size()];
        uint32_t *ptr = value;
        for(sack_type::const_iterator it = edges.begin(); it != edges.end(); ++it)
            *(ptr++) = Endian::host_to_be(*it);
    }
    add_option(
        option(
            SACK, 
            (uint8_t)(sizeof(uint32_t) * edges.size()), 
            (const uint8_t*)value
        )
    );
    delete[] value;
}

TCP::sack_type TCP::sack() const {
    const option *option = search_option(SACK);
    if(!option || (option->data_size() % sizeof(uint32_t)) != 0)
        throw option_not_found();
    const uint32_t *ptr = (const uint32_t*)option->data_ptr();
    const uint32_t *end = ptr + (option->data_size() / sizeof(uint32_t));
    sack_type edges(end - ptr);
    sack_type::iterator it = edges.begin();
    while(ptr < end)
        *it++ = Endian::host_to_be(*(ptr++));
    return edges;
}

void TCP::timestamp(uint32_t value, uint32_t reply) {
    uint64_t buffer = (uint64_t(value) << 32) | reply;
    buffer = Endian::host_to_be(buffer);
    add_option(option(TSOPT, 8, (uint8_t*)&buffer));
}

std::pair<uint32_t, uint32_t> TCP::timestamp() const {
    const option *option = search_option(TSOPT);
    if(!option || option->data_size() != (sizeof(uint32_t) << 1))
        throw option_not_found();
    uint64_t buffer = *(const uint64_t*)option->data_ptr();
    buffer = Endian::be_to_host(buffer);
    return std::make_pair(static_cast<uint32_t>(buffer >> 32), buffer & 0xffffffff);
}

void TCP::altchecksum(AltChecksums value) {
    uint8_t int_value = value;
    add_option(option(ALTCHK, 1, &int_value));
}

TCP::AltChecksums TCP::altchecksum() const {
    return static_cast<AltChecksums>(generic_search<uint8_t>(ALTCHK));
}

small_uint<1> TCP::get_flag(Flags tcp_flag) {
    switch(tcp_flag) {
        case FIN:
            return _tcp.fin;
            break;
        case SYN:
            return _tcp.syn;
            break;
        case RST:
            return _tcp.rst;
            break;
        case PSH:
            return _tcp.psh;
            break;
        case ACK:
            return _tcp.ack;
            break;
        case URG:
            return _tcp.urg;
            break;
        case ECE:
            return _tcp.ece;
            break;
        case CWR:
            return _tcp.cwr;
            break;
        default:
            return 0;
            break;
    };
}

void TCP::set_flag(Flags tcp_flag, small_uint<1> value) {
    switch(tcp_flag) {
        case FIN:
            _tcp.fin = value;
            break;
        case SYN:
            _tcp.syn = value;
            break;
        case RST:
            _tcp.rst = value;
            break;
        case PSH:
            _tcp.psh = value;
            break;
        case ACK:
            _tcp.ack = value;
            break;
        case URG:
            _tcp.urg = value;
            break;
        case ECE:
            _tcp.ece = value;
            break;
        case CWR:
            _tcp.cwr = value;
            break;
    };
}

void TCP::add_option(OptionTypes opt, uint8_t length, const uint8_t *data) {
    add_option(option(opt, data, data + length));
}

void TCP::add_option(const option &opt) {
    _options.push_back(opt);
    internal_add_option(opt);
}

uint32_t TCP::header_size() const {
    return sizeof(tcphdr) + _total_options_size;
}

void TCP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= header_size());
    uint8_t *tcp_start = buffer;
    buffer += sizeof(tcphdr);
    _tcp.doff = (sizeof(tcphdr) + _total_options_size) / sizeof(uint32_t);
    for(options_type::iterator it = _options.begin(); it != _options.end(); ++it)
        buffer = write_option(*it, buffer);

    if(_options_size < _total_options_size) {
        uint8_t padding = _options_size;
        while(padding < _total_options_size) {
            *(buffer++) = 1;
            padding++;
        }
    }

    memcpy(tcp_start, &_tcp, sizeof(tcphdr));

    if(!_tcp.check) {
        const Tins::IP *ip_packet = dynamic_cast<const Tins::IP*>(parent);
        if(ip_packet) {
            uint32_t checksum = Utils::pseudoheader_checksum(ip_packet->src_addr(),  
                                                             ip_packet->dst_addr(), 
                                                             size(), Constants::IP::PROTO_TCP) +
                                Utils::do_checksum(tcp_start, tcp_start + total_sz);
            while (checksum >> 16)
                checksum = (checksum & 0xffff) + (checksum >> 16);
            
            ((tcphdr*)tcp_start)->check = Endian::host_to_be<uint16_t>(~checksum);
        }
        else {
            const Tins::IPv6 *ipv6_packet = dynamic_cast<const Tins::IPv6*>(parent);
            if(ipv6_packet) {
                uint32_t checksum = Utils::pseudoheader_checksum(ipv6_packet->src_addr(),  
                                                             ipv6_packet->dst_addr(), 
                                                             size(), Constants::IP::PROTO_TCP) +
                                            Utils::do_checksum(tcp_start, tcp_start + total_sz);
                while (checksum >> 16)
                    checksum = (checksum & 0xffff) + (checksum >> 16);
                
                ((tcphdr*)tcp_start)->check = Endian::host_to_be<uint16_t>(~checksum);
            }
        }
    }
    
    _tcp.check = 0;
}

const TCP::option *TCP::search_option(OptionTypes opt) const {
    for(options_type::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        if(it->option() == opt)
            return &(*it);
    }
    return 0;
}

/* options */

uint8_t *TCP::write_option(const option &opt, uint8_t *buffer) {
    if(opt.option() == 0 || opt.option() == 1) {
        *buffer = opt.option();
        return buffer + 1;
    }
    else {
        buffer[0] = opt.option();
        buffer[1] = opt.length_field();
        // only add the identifier and size field sizes if the length
        // field hasn't been spoofed.
        if(opt.length_field() == opt.data_size())
            buffer[1] += (sizeof(uint8_t) << 1);
        return std::copy(opt.data_ptr(), opt.data_ptr() + opt.data_size(), buffer + 2);
    }
}

#if TINS_IS_CXX11
void TCP::add_option(option &&opt) {
    internal_add_option(opt);
    _options.push_back(std::move(opt));
}
#endif

void TCP::internal_add_option(const option &opt) {
    uint8_t padding;
    
    _options_size += sizeof(uint8_t);
    // SACK_OK contains length but not data....
    if(opt.data_size() || opt.option() == SACK_OK)
        _options_size += sizeof(uint8_t);
        
    _options_size += opt.data_size();
    
    padding = _options_size & 3;
    _total_options_size = (padding) ? _options_size - padding + 4 : _options_size;
}

bool TCP::matches_response(uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(tcphdr))
        return false;
    const tcphdr *tcp_ptr = (const tcphdr*)ptr;
    if(tcp_ptr->sport == _tcp.dport && tcp_ptr->dport == _tcp.sport) {
        uint32_t sz = std::min<uint32_t>(total_sz, tcp_ptr->doff * sizeof(uint32_t));
        return inner_pdu() ? inner_pdu()->matches_response(ptr + sz, total_sz - sz) : true;
    }
    else
        return false;
}

}

