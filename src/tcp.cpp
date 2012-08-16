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
#include "tcp.h"
#include "ip.h"
#include "constants.h"
#include "rawpdu.h"
#include "utils.h"


const uint16_t Tins::TCP::DEFAULT_WINDOW = 32678;

Tins::TCP::TCP(uint16_t dport, uint16_t sport) 
: PDU(Constants::IP::PROTO_TCP), _options_size(0), _total_options_size(0) 
{
    std::memset(&_tcp, 0, sizeof(tcphdr));
    this->dport(dport);
    this->sport(sport);
    data_offset(sizeof(tcphdr) / sizeof(uint32_t));
    window(DEFAULT_WINDOW);
}

Tins::TCP::TCP(const uint8_t *buffer, uint32_t total_sz) 
: PDU(Constants::IP::PROTO_TCP) 
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
                    add_option((Option)args[0], args[1], buffer + index);
                else
                    add_option((Option)args[0], args[1], 0);
                index += args[1];
            }
            else
                add_option((Option)args[0], 0, 0);
        }
        buffer += index;
        total_sz -= index;
    }
    if(total_sz)
        inner_pdu(new RawPDU(buffer, total_sz));
}

void Tins::TCP::dport(uint16_t new_dport) {
    _tcp.dport = Utils::host_to_be(new_dport);
}

void Tins::TCP::sport(uint16_t new_sport) {
    _tcp.sport = Utils::host_to_be(new_sport);
}

void Tins::TCP::seq(uint32_t new_seq) {
    _tcp.seq = Utils::host_to_be(new_seq);
}

void Tins::TCP::ack_seq(uint32_t new_ack_seq) {
    _tcp.ack_seq = Utils::host_to_be(new_ack_seq);
}

void Tins::TCP::window(uint16_t new_window) {
    _tcp.window = Utils::host_to_be(new_window);
}

void Tins::TCP::check(uint16_t new_check) {
    _tcp.check = Utils::host_to_be(new_check);
}

void Tins::TCP::urg_ptr(uint16_t new_urg_ptr) {
    _tcp.urg_ptr = Utils::host_to_be(new_urg_ptr);
}

void Tins::TCP::payload(uint8_t *new_payload, uint32_t new_payload_size) {
    inner_pdu(new RawPDU(new_payload, new_payload_size));
}

void Tins::TCP::data_offset(uint8_t new_doff) {
    this->_tcp.doff = new_doff;
}

void Tins::TCP::add_mss_option(uint16_t value) {
    value = Utils::host_to_be(value);
    add_option(MSS, 2, (uint8_t*)&value);
}

bool Tins::TCP::search_mss_option(uint16_t *value) {
    if(!generic_search(MSS, value))
        return false;
    *value = Utils::host_to_be(*value);
    return true;
}

void Tins::TCP::add_winscale_option(uint8_t value) {
    add_option(WSCALE, 1, &value);
}

bool Tins::TCP::search_winscale_option(uint8_t *value) {
    return generic_search(WSCALE, value);
}

void Tins::TCP::add_sack_permitted_option() {
    add_option(SACK_OK, 0, 0);
}

bool Tins::TCP::search_sack_permitted_option() {
    return search_option(SACK_OK);
}

void Tins::TCP::add_sack_option(const std::list<uint32_t> &edges) {
    uint32_t *value = 0;
    if(edges.size()) {
        value = new uint32_t[edges.size()];
        uint32_t *ptr = value;
        for(std::list<uint32_t>::const_iterator it = edges.begin(); it != edges.end(); ++it)
            *(ptr++) = Utils::host_to_be(*it);
    }
    add_option(SACK, (uint8_t)(sizeof(uint32_t) * edges.size()), (const uint8_t*)value);
    delete[] value;
}

bool Tins::TCP::search_sack_option(std::list<uint32_t> *edges) {
    const TCPOption *option = search_option(SACK);
    if(!option || (option->value.size() % sizeof(uint32_t)) != 0)
        return false;
    const uint32_t *ptr = (const uint32_t*)&option->value[0];
    const uint32_t *end = ptr + (option->value.size() / sizeof(uint32_t));
    while(ptr < end)
        edges->push_back(Utils::host_to_be(*(ptr++)));
    return true;
}

void Tins::TCP::add_timestamp_option(uint32_t value, uint32_t reply) {
    uint64_t buffer = ((uint64_t)Utils::host_to_be(reply) << 32) | Utils::host_to_be(value);
    add_option(TSOPT, 8, (uint8_t*)&buffer);
}

bool Tins::TCP::search_timestamp_option(uint32_t *value, uint32_t *reply) {
    const TCPOption *option = search_option(TSOPT);
    if(!option || option->value.size() != (sizeof(uint32_t) << 1))
        return false;
    const uint32_t *ptr = (const uint32_t*)&option->value[0];
    *value = Utils::host_to_be(*(ptr++));
    *reply = Utils::host_to_be(*(ptr));
    return true;
}

void Tins::TCP::add_altchecksum_option(AltChecksums value) {
    add_option(ALTCHK, 1, (const uint8_t*)&value);
}

bool Tins::TCP::search_altchecksum_option(uint8_t *value) {
    return generic_search(ALTCHK, value);
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

void Tins::TCP::add_option(Option tcp_option, uint8_t length, const uint8_t *data) {
    uint8_t padding;
    _options.push_back(TCPOption(tcp_option, length, data));
    
    _options_size += sizeof(uint8_t);
    // SACK_OK contains length but not data....
    if(length || tcp_option == SACK_OK)
        _options_size += sizeof(uint8_t);
        
    if(data)
        _options_size += length;
    
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
        uint8_t padding = _options_size;
        while(padding < _total_options_size) {
            *(buffer++) = 1;
            padding++;
        }
    }

    const Tins::IP *ip_packet = dynamic_cast<const Tins::IP*>(parent);
    memcpy(tcp_start, &_tcp, sizeof(tcphdr));
    if(!_tcp.check && ip_packet) {
        uint32_t checksum = Utils::pseudoheader_checksum(ip_packet->src_addr(),  
                                                         ip_packet->dst_addr(), 
                                                         size(), Constants::IP::PROTO_TCP) +
                            Utils::do_checksum(tcp_start, tcp_start + total_sz);
        while (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16);
        
        ((tcphdr*)tcp_start)->check = Utils::host_to_be<uint16_t>(~checksum);
    }
    _tcp.check = 0;
}

const Tins::TCP::TCPOption *Tins::TCP::search_option(Option opt) const {
    for(std::list<TCPOption>::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        if(it->option == opt)
            return &(*it);
    }
    return 0;
}

/* TCPOptions */

uint8_t *Tins::TCP::TCPOption::write(uint8_t *buffer) {
    if(option == 0 || option == 1) {
        *buffer = option;
        return buffer + 1;
    }
    else {
        buffer[0] = option;
        buffer[1] = value.size() + (sizeof(uint8_t) << 1);
        if(!value.empty())
            std::copy(value.begin(), value.end(), buffer + 2);
        return buffer + buffer[1];
    }
}

