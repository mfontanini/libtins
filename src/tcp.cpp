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
#include "tcp.h"
#include "ip.h"
#include "rawpdu.h"
#include "utils.h"


const uint16_t Tins::TCP::DEFAULT_WINDOW = 32678;

Tins::TCP::TCP(uint16_t dport, uint16_t sport) : PDU(IPPROTO_TCP), _options_size(0), _total_options_size(0) {
    std::memset(&_tcp, 0, sizeof(tcphdr));
    this->dport(dport);
    this->sport(sport);
    this->data_offset(sizeof(tcphdr) / sizeof(uint32_t));
    this->window(DEFAULT_WINDOW);
    this->check(0);
}

Tins::TCP::TCP(const TCP &other) : PDU(other) {
    copy_fields(&other);
}

Tins::TCP &Tins::TCP::operator= (const TCP &other) {
    copy_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

Tins::TCP::TCP(const uint8_t *buffer, uint32_t total_sz) : PDU(IPPROTO_TCP) {
    if(total_sz < sizeof(tcphdr))
        throw std::runtime_error("Not enough size for an TCP header in the buffer.");
    std::memcpy(&_tcp, buffer, sizeof(tcphdr));
    
    buffer += sizeof(tcphdr);
    total_sz -= sizeof(tcphdr);
    
    uint32_t index = 0, header_end = (data_offset() * sizeof(uint32_t)) - sizeof(tcphdr);
    if(total_sz >= header_end) {
        uint8_t args[2] = {0};
        while(index < header_end) {
            for(unsigned i(0); i < 2 && args[0] != NOP; ++i) {
                args[i] = buffer[index++];
                if(index == header_end)
                    throw std::runtime_error("Not enought size for a TCP header in the buffer.");
            }
            // We don't want to store NOPs and EOLs
            if(args[0] != NOP && args[0] != EOL)  {
                if(args[1]) {
                    // Not enough size for this option
                    if(header_end - index < args[1] - (sizeof(uint8_t) << 1)) {
                        throw std::runtime_error("Not enought size for a TCP header in the buffer.");
                    }
                    args[1] -= (sizeof(uint8_t) << 1);
                    add_option((Options)args[0], args[1], buffer + index);
                }
                index += args[1];
            }
            else if(args[0] == EOL)
                index = header_end;
            else // Skip the NOP
                args[0] = 0;
        }
        buffer += index;
        total_sz -= index;
        _total_options_size = header_end;
        _options_size = (_total_options_size / 4) * 4;
    }
    if(total_sz)
        inner_pdu(new RawPDU(buffer, total_sz));
}

Tins::TCP::~TCP() {
    for(std::list<TCPOption>::iterator it = _options.begin(); it != _options.end(); ++it)
        delete[] it->data;
}

void Tins::TCP::dport(uint16_t new_dport) {
    _tcp.dport = Utils::net_to_host_s(new_dport);
}

void Tins::TCP::sport(uint16_t new_sport) {
    _tcp.sport = Utils::net_to_host_s(new_sport);
}

void Tins::TCP::seq(uint32_t new_seq) {
    _tcp.seq = Utils::net_to_host_l(new_seq);
}

void Tins::TCP::ack_seq(uint32_t new_ack_seq) {
    _tcp.ack_seq = Utils::net_to_host_l(new_ack_seq);
}

void Tins::TCP::window(uint16_t new_window) {
    _tcp.window = Utils::net_to_host_s(new_window);
}

void Tins::TCP::check(uint16_t new_check) {
    _tcp.check = Utils::net_to_host_s(new_check);
}

void Tins::TCP::urg_ptr(uint16_t new_urg_ptr) {
    _tcp.urg_ptr = Utils::net_to_host_s(new_urg_ptr);
}

void Tins::TCP::payload(uint8_t *new_payload, uint32_t new_payload_size) {
    inner_pdu(new RawPDU(new_payload, new_payload_size));
}

void Tins::TCP::data_offset(uint8_t new_doff) {
    this->_tcp.doff = new_doff;
}

void Tins::TCP::set_mss(uint16_t value) {
    value = Utils::net_to_host_s(value);
    add_option(MSS, 2, (uint8_t*)&value);
}

void Tins::TCP::set_timestamp(uint32_t value, uint32_t reply) {
    uint64_t buffer = ((uint64_t)Utils::net_to_host_l(reply) << 32) | Utils::net_to_host_l(value);
    add_option(TSOPT, 8, (uint8_t*)&buffer);
}

uint8_t Tins::TCP::get_flag(Flags tcp_flag) {
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

void Tins::TCP::set_flag(Flags tcp_flag, uint8_t value) {
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

void Tins::TCP::add_option(Options tcp_option, uint8_t length, const uint8_t *data) {
    uint8_t *new_data = new uint8_t[length], padding;
    memcpy(new_data, data, length);
    _options.push_back(TCPOption(tcp_option, length, new_data));
    _options_size += length + (sizeof(uint8_t) << 1);
    padding = _options_size & 3;
    _total_options_size = (padding) ? _options_size - padding + 4 : _options_size;
}

uint32_t Tins::TCP::header_size() const {
    return sizeof(tcphdr) + _total_options_size;
}

void Tins::TCP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= header_size());
    uint8_t *tcp_start = buffer;
    buffer += sizeof(tcphdr);
    _tcp.doff = (sizeof(tcphdr) + _total_options_size) / sizeof(uint32_t);
    for(std::list<TCPOption>::iterator it = _options.begin(); it != _options.end(); ++it)
        buffer = it->write(buffer);

    if(_options_size < _total_options_size) {
        uint8_t padding = _total_options_size;
        while(padding < _options_size) {
            *(buffer++) = 1;
            padding++;
        }
    }

    const Tins::IP *ip_packet = dynamic_cast<const Tins::IP*>(parent);
    memcpy(tcp_start, &_tcp, sizeof(tcphdr));
    if(!_tcp.check && ip_packet) {
        uint32_t checksum = PDU::pseudoheader_checksum(ip_packet->src_addr(), ip_packet->dst_addr(), size(), IPPROTO_TCP) +
                            PDU::do_checksum(tcp_start, tcp_start + total_sz);
        while (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16);
        ((tcphdr*)tcp_start)->check = Utils::net_to_host_s(~checksum);
    }
    _tcp.check = 0;
}


/* TCPOptions */

uint8_t *Tins::TCP::TCPOption::write(uint8_t *buffer) {
    if(kind == 1) {
        *buffer = kind;
        return buffer + 1;
    }
    else {
        buffer[0] = kind;
        buffer[1] = length + (sizeof(uint8_t) << 1);
        memcpy(buffer + 2, data, length);
        return buffer + length + (sizeof(uint8_t) << 1);
    }
}

void Tins::TCP::copy_fields(const TCP *other) {
    std::memcpy(&_tcp, &other->_tcp, sizeof(_tcp));
    for(std::list<TCPOption>::const_iterator it = other->_options.begin(); it != other->_options.end(); ++it) {
        TCPOption opt(it->kind, it->length);
        if(it->data) {
            opt.data = new uint8_t[it->length];
            std::memcpy(opt.data, it->data, it->length);
        }
        _options.push_back(opt);
    }
    _options_size = other->_options_size;
    _total_options_size = other->_total_options_size;
}

Tins::PDU *Tins::TCP::clone_pdu() const {
    TCP *new_pdu = new TCP();
    new_pdu->copy_fields(this);
    return new_pdu;
}

