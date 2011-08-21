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

#include <cassert>
#include <cstring>
#include <stdexcept>

#ifndef WIN32
    #include <net/ethernet.h>
    #include <netpacket/packet.h>
    #include <netinet/in.h>
#endif

#include "ieee802-11.h"
#include "rawpdu.h"
#include "utils.h"

using namespace std;

Tins::IEEE802_11::IEEE802_11(const std::string& iface, const uint8_t* dst_hw_addr, const uint8_t* src_hw_addr, PDU* child) throw (std::runtime_error) : PDU(ETHERTYPE_IP, child) {
    memset(&this->_header, 0, sizeof(ieee80211_header));
    if(dst_hw_addr)
        this->dst_addr(dst_hw_addr);
    if(src_hw_addr)
        this->src_addr(src_hw_addr);
    this->iface(iface);

}


Tins::IEEE802_11::IEEE802_11(uint32_t iface_index, const uint8_t* dst_hw_addr, const uint8_t* src_hw_addr, PDU* child) : PDU(ETHERTYPE_IP, child) {
    memset(&this->_header, 0, sizeof(ieee80211_header));
    if(dst_hw_addr)
        this->dst_addr(dst_hw_addr);
    if(src_hw_addr)
        this->src_addr(src_hw_addr);
    this->iface(iface_index);
}

Tins::IEEE802_11::IEEE802_11(const uint8_t *buffer, uint32_t total_sz) : PDU(ETHERTYPE_IP) {

}

void Tins::IEEE802_11::protocol(uint8_t new_proto) {
    this->_header.control.protocol = new_proto;
}

void Tins::IEEE802_11::type(uint8_t new_type) {
    this->_header.control.type = new_type;
}

void Tins::IEEE802_11::subtype(uint8_t new_subtype) {
    this->_header.control.subtype = new_subtype;
}

void Tins::IEEE802_11::to_ds(bool new_value) {
    this->_header.control.to_ds = (new_value)? 1 : 0;
}

void Tins::IEEE802_11::from_ds(bool new_value) {
    this->_header.control.from_ds = (new_value)? 1 : 0;
}

void Tins::IEEE802_11::more_frag(bool new_value) {
    this->_header.control.more_frag = (new_value)? 1 : 0;
}

void Tins::IEEE802_11::retry(bool new_value) {
    this->_header.control.retry = (new_value)? 1 : 0;
}

void Tins::IEEE802_11::power_mgmt(bool new_value) {
    this->_header.control.power_mgmt = (new_value)? 1 : 0;
}

void Tins::IEEE802_11::wep(bool new_value) {
    this->_header.control.wep = (new_value)? 1 : 0;
}

void Tins::IEEE802_11::order(bool new_value) {
    this->_header.control.order = (new_value)? 1 : 0;
}

void Tins::IEEE802_11::duration_id(uint16_t new_duration_id) {
    this->_header.duration_id = Utils::net_to_host_s(new_duration_id);
}

void Tins::IEEE802_11::dst_addr(const uint8_t* new_dst_addr) {
    memcpy(this->_header.dst_addr, new_dst_addr, 6);
}

void Tins::IEEE802_11::src_addr(const uint8_t* new_src_addr) {
    memcpy(this->_header.src_addr, new_src_addr, 6);
}

void Tins::IEEE802_11::filter_addr(const uint8_t* new_filter_addr) {
    memcpy(this->_header.filter_addr, new_filter_addr, 6);
}

void Tins::IEEE802_11::frag_num(uint8_t new_frag_num) {
    this->_header.seq_control.frag_number = new_frag_num;
}

void Tins::IEEE802_11::seq_num(uint16_t new_seq_num) {
    this->_header.seq_control.seq_number = Utils::net_to_host_s(new_seq_num);
}

void Tins::IEEE802_11::opt_addr(const uint8_t* new_opt_addr) {
    memcpy(this->_opt_addr, new_opt_addr, 6);
}

void Tins::IEEE802_11::iface(uint32_t new_iface_index) {
    this->_iface_index = new_iface_index;
}

void Tins::IEEE802_11::iface(const std::string& new_iface) throw (std::runtime_error) {
    if (!Tins::Utils::interface_id(new_iface, this->_iface_index)) {
        throw std::runtime_error("Invalid interface name!");
    }
}

uint32_t Tins::IEEE802_11::header_size() const {
    uint32_t sz = sizeof(ieee80211_header);
    if (this->to_ds() && this->from_ds())
        sz += 6;
    return sz;
}

bool Tins::IEEE802_11::send(PacketSender* sender) {
    struct sockaddr_ll addr;

    memset(&addr, 0, sizeof(struct sockaddr_ll));

    addr.sll_family = Utils::net_to_host_s(PF_PACKET);
    addr.sll_protocol = Utils::net_to_host_s(ETH_P_ALL);
    addr.sll_halen = 6;
    addr.sll_ifindex = this->_iface_index;
    memcpy(&(addr.sll_addr), this->_header.dst_addr, 6);

    return sender->send_l2(this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
}

void Tins::IEEE802_11::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    uint32_t my_sz = header_size();
    assert(total_sz >= my_sz);

    memcpy(buffer, &this->_header, sizeof(ieee80211_header));
    if (this->to_ds() && this->from_ds()) {
        memcpy(buffer + sizeof(ieee80211_header), this->_opt_addr, 6);
    }
}

Tins::IEEE802_11::IEEE802_11(const ieee80211_header *header_ptr) : PDU(ETHERTYPE_IP) {

}
