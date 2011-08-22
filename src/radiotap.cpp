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
#include "ieee802-11.h"
#include "utils.h"


Tins::RadioTap::RadioTap(const std::string &iface) throw (std::runtime_error) : PDU(0xff) {
    if(!Utils::interface_id(iface, _iface_index))
        throw std::runtime_error("Invalid interface name!");
    std::memset(&_radio, 0, sizeof(_radio));
}

Tins::RadioTap::RadioTap(uint32_t iface_index) : PDU(0xff), _iface_index(iface_index) {
    std::memset(&_radio, 0, sizeof(_radio));
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

void Tins::RadioTap::present(uint8_t new_present) {
    _radio.it_present = new_present;
}

uint32_t Tins::RadioTap::header_size() const {
    return sizeof(_radio);
}

bool Tins::RadioTap::send(PacketSender* sender) {
    struct sockaddr_ll addr;

    memset(&addr, 0, sizeof(struct sockaddr_ll));

    addr.sll_family = Utils::net_to_host_s(PF_PACKET);
    addr.sll_protocol = Utils::net_to_host_s(ETH_P_ALL);
    addr.sll_halen = 6;
    addr.sll_ifindex = _iface_index;
    
    Tins::IEEE802_11 *wlan = dynamic_cast<Tins::IEEE802_11*>(inner_pdu());
    if(wlan)
        memcpy(&(addr.sll_addr), wlan->dst_addr(), 6);

    return sender->send_l2(this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
}

void Tins::RadioTap::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    uint32_t sz = header_size();
    assert(total_sz >= sz);
    if(!_radio.it_len)
        _radio.it_len = sz;
    memcpy(buffer, &_radio, sizeof(_radio));
}
