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
    #include <net/ethernet.h>
    #include <netpacket/packet.h>
#endif
#include "radiotap.h"
#include "dot11.h"
#include "utils.h"


Tins::RadioTap::RadioTap(const NetworkInterface &iface, PDU *child)
: PDU(0xff, child), _iface(iface), _options_size(0)
{
    std::memset(&_radio, 0, sizeof(_radio));
    init();
}

Tins::RadioTap::RadioTap(const uint8_t *buffer, uint32_t total_sz) : PDU(0xff) {
    static const std::string msg("Not enough size for an RadioTap header in the buffer.");
    if(total_sz < sizeof(_radio))
        throw std::runtime_error(msg);
    const uint8_t *buffer_start = buffer;
    std::memcpy(&_radio, buffer, sizeof(_radio));
    buffer += sizeof(_radio);
    total_sz -= sizeof(_radio);
    if(_radio.tsft) {
        if(total_sz < sizeof(_tsft))
            throw std::runtime_error(msg);
        memcpy(&_tsft, buffer, sizeof(_tsft));
        buffer += sizeof(_tsft);
        total_sz -= sizeof(_tsft);
    }
    if(_radio.flags) {
        if(total_sz < sizeof(_flags))
            throw std::runtime_error(msg);
        memcpy(&_flags, buffer, sizeof(_flags));
        buffer += sizeof(_flags);
        total_sz -= sizeof(_flags);
    }
    if(_radio.rate) {
        if(total_sz < sizeof(_rate))
            throw std::runtime_error(msg);
        memcpy(&_rate, buffer, sizeof(_rate));
        buffer += sizeof(_rate);
        total_sz -= sizeof(_rate);
    }
    if(_radio.channel) {
        if(((buffer_start - buffer) & 1) == 1) {
            buffer++;
            total_sz--;
        }
        if(total_sz < sizeof(uint32_t))
            throw std::runtime_error(msg);
        memcpy(&_channel_freq, buffer, sizeof(_channel_freq));
        buffer += sizeof(_channel_freq);
        memcpy(&_channel_type, buffer, sizeof(_channel_type));
        buffer += sizeof(_channel_type);
        total_sz -= sizeof(uint32_t);
    }
    if(_radio.dbm_signal) {
        if(total_sz < sizeof(_dbm_signal))
            throw std::runtime_error(msg);
        memcpy(&_dbm_signal, buffer, sizeof(_dbm_signal));
        buffer += sizeof(_dbm_signal);
        total_sz -= sizeof(_dbm_signal);
    }
    if(_radio.antenna) {
        if(total_sz < sizeof(_antenna))
            throw std::runtime_error(msg);
        memcpy(&_antenna, buffer, sizeof(_antenna));
        buffer += sizeof(_antenna);
        total_sz -= sizeof(_antenna);
    }
    if(_radio.rx_flags) {
        if(((buffer_start - buffer) & 1) == 1) {
            buffer++;
            total_sz--;
        }
        if(total_sz < sizeof(_rx_flags))
            throw std::runtime_error(msg);
        memcpy(&_rx_flags, buffer, sizeof(_rx_flags));
        buffer += sizeof(_rx_flags);
        total_sz -= sizeof(_rx_flags);
    }
    if(total_sz)
        inner_pdu(Dot11::from_bytes(buffer, total_sz));
}

void Tins::RadioTap::init() {
    channel(Utils::channel_to_mhz(1), 0xa0);
    flags(FCS);
    tsft(0);
    dbm_signal(0xce);
    rx_flag(0);
    antenna(0);
}

void Tins::RadioTap::version(uint8_t new_version) {
    _radio.it_version = new_version;
}
        
void Tins::RadioTap::padding(uint8_t new_padding) {
    _radio.it_pad = new_padding;
}

void Tins::RadioTap::length(uint8_t new_length) {
    _radio.it_len = new_length;
}

void Tins::RadioTap::tsft(uint64_t new_tsft) {
    _tsft = new_tsft;
    if(!_radio.tsft)
        _options_size += sizeof(_tsft);
    _radio.tsft = 1;
}

void Tins::RadioTap::flags(FrameFlags new_flags) {
    _flags = (uint8_t)new_flags;
    if(!_radio.flags)
        _options_size += sizeof(_flags);
    _radio.flags = 1;
}

void Tins::RadioTap::rate(uint8_t new_rate) {
    _rate = new_rate;
    if(!_radio.rate)
        _options_size += sizeof(uint8_t);
    _radio.rate = 1;
}

void Tins::RadioTap::channel(uint16_t new_freq, uint16_t new_type) {
    _channel_freq = new_freq;
    _channel_type = new_type;
    if(!_radio.channel)
        _options_size += sizeof(_channel_freq) + sizeof(_channel_type);
    _radio.channel = 1;
}
void Tins::RadioTap::dbm_signal(uint8_t new_dbm_signal) {
    _dbm_signal = new_dbm_signal;
    if(!_radio.dbm_signal)
        _options_size += sizeof(_dbm_signal);
    _radio.dbm_signal = 1;
}

void Tins::RadioTap::antenna(uint8_t new_antenna) {
    _antenna = new_antenna;
    if(!_radio.antenna)
        _options_size += sizeof(_antenna);
    _radio.antenna = 1;
}

void Tins::RadioTap::rx_flag(uint16_t new_rx_flag) {
    _rx_flags = new_rx_flag;
    if(!_radio.rx_flags)
        _options_size += sizeof(_rx_flags);
    _radio.rx_flags = 1;
}

uint32_t Tins::RadioTap::header_size() const {
    uint8_t padding = 0;
    if((_radio.flags ^ _radio.rate) == 1)
        padding++;
    if((_radio.dbm_signal ^ _radio.antenna) == 1)
        padding++;
    return sizeof(_radio) + _options_size + padding;
}

uint32_t Tins::RadioTap::trailer_size() const {
    // will be sizeof(uint32_t) if the FCS-at-the-end bit is on.
    return ((_flags & 0x10) != 0) ? sizeof(uint32_t) : 0;
}

bool Tins::RadioTap::send(PacketSender* sender) {
    struct sockaddr_ll addr;

    memset(&addr, 0, sizeof(struct sockaddr_ll));

    addr.sll_family = Utils::host_to_be<uint16_t>(PF_PACKET);
    addr.sll_protocol = Utils::host_to_be<uint16_t>(ETH_P_ALL);
    addr.sll_halen = 6;
    addr.sll_ifindex = _iface.id();
    
    Tins::Dot11 *wlan = dynamic_cast<Tins::Dot11*>(inner_pdu());
    if(wlan) {
        Dot11::address_type dot11_addr(wlan->addr1());
        std::copy(dot11_addr.begin(), dot11_addr.end(), addr.sll_addr);
        //memcpy(&(addr.sll_addr), wlan->addr1(), 6);
    }

    return sender->send_l2(this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
}

void Tins::RadioTap::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    uint32_t sz = header_size();
    uint8_t *buffer_start = buffer;
    assert(total_sz >= sz);
    if(!_radio.it_len)
        _radio.it_len = sz;
    memcpy(buffer, &_radio, sizeof(_radio));
    buffer += sizeof(_radio);
    if(_radio.tsft) {
        memcpy(buffer, &_tsft, sizeof(_tsft));
        buffer += sizeof(_tsft);
    }
    if(_radio.flags) {
        memcpy(buffer, &_flags, sizeof(_flags));
        buffer += sizeof(_flags);
    }
    if(_radio.rate) {
        memcpy(buffer, &_rate, sizeof(_rate));
        buffer += sizeof(_rate);
    }
    if(_radio.channel) {
        if(((buffer_start - buffer) & 1) == 1)
            *(buffer++) = 0;
        memcpy(buffer, &_channel_freq, sizeof(_channel_freq));
        buffer += sizeof(_channel_freq);
        memcpy(buffer, &_channel_type, sizeof(_channel_type));
        buffer += sizeof(_channel_type);
    }
    if(_radio.dbm_signal) {
        memcpy(buffer, &_dbm_signal, sizeof(_dbm_signal));
        buffer += sizeof(_dbm_signal);
    }
    if(_radio.antenna) {
        memcpy(buffer, &_antenna, sizeof(_antenna));
        buffer += sizeof(_antenna);
    }
    if(_radio.rx_flags) {
        if(((buffer_start - buffer) & 1) == 1)
            *(buffer++) = 0;
        memcpy(buffer, &_rx_flags, sizeof(_rx_flags));
        buffer += sizeof(_rx_flags);
    }
    if((_flags & 0x10) != 0 && inner_pdu())
        *(uint32_t*)(buffer + inner_pdu()->size()) = Utils::crc32(buffer, inner_pdu()->size());
}
