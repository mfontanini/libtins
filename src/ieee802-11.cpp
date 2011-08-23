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

const uint8_t *Tins::IEEE802_11::BROADCAST = (const uint8_t*)"\xff\xff\xff\xff\xff\xff";

Tins::IEEE802_11::IEEE802_11(const uint8_t* dst_hw_addr, const uint8_t* src_hw_addr, PDU* child) : PDU(ETHERTYPE_IP, child), _options_size(0) {
    memset(&this->_header, 0, sizeof(ieee80211_header));
    if(dst_hw_addr)
        this->dst_addr(dst_hw_addr);
    if(src_hw_addr)
        this->src_addr(src_hw_addr);
}

Tins::IEEE802_11::IEEE802_11(const std::string& iface, const uint8_t* dst_hw_addr, const uint8_t* src_hw_addr, PDU* child) throw (std::runtime_error) : PDU(ETHERTYPE_IP, child), _options_size(0) {
    memset(&this->_header, 0, sizeof(ieee80211_header));
    if(dst_hw_addr)
        this->dst_addr(dst_hw_addr);
    if(src_hw_addr)
        this->src_addr(src_hw_addr);
    this->iface(iface);
}


Tins::IEEE802_11::IEEE802_11(uint32_t iface_index, const uint8_t* dst_hw_addr, const uint8_t* src_hw_addr, PDU* child) : PDU(ETHERTYPE_IP, child), _options_size(0) {
    memset(&this->_header, 0, sizeof(ieee80211_header));
    if(dst_hw_addr)
        this->dst_addr(dst_hw_addr);
    if(src_hw_addr)
        this->src_addr(src_hw_addr);
    this->iface(iface_index);
}

Tins::IEEE802_11::IEEE802_11(const uint8_t *buffer, uint32_t total_sz) : PDU(ETHERTYPE_IP), _options_size(0) {

}

Tins::IEEE802_11::~IEEE802_11() {
    while(_options.size()) {
        delete[] _options.front().value;
        _options.pop_front();
    }
}

Tins::IEEE802_11::IEEE802_11_Option::IEEE802_11_Option(uint8_t opt, uint8_t len, const uint8_t *val) : option(opt), length(len) {
    value = new uint8_t[len];
    std::memcpy(value, val, len);
}

void Tins::IEEE802_11::add_tagged_option(TaggedOption opt, uint8_t len, const uint8_t *val) {
    uint32_t opt_size = len + (sizeof(uint8_t) << 1);
    _options.push_back(IEEE802_11_Option((uint8_t)opt, len, val));
    _options_size += opt_size;
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
    uint32_t sz = sizeof(ieee80211_header) + _options_size;
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
    buffer += sizeof(ieee80211_header);
    if (this->to_ds() && this->from_ds()) {
        memcpy(buffer, this->_opt_addr, 6);
        buffer += 6;
        total_sz -= 6;
    }

    uint32_t child_len = write_fixed_parameters(buffer, total_sz - sizeof(ieee80211_header) - _options_size);
    buffer += child_len;
    assert(total_sz > child_len + _options_size);
    for(std::list<IEEE802_11_Option>::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        *(buffer++) = it->option;
        *(buffer++) = it->length;
        std::memcpy(buffer, it->value, it->length);
        buffer += it->length;
    }
}

Tins::IEEE802_11::IEEE802_11(const ieee80211_header *header_ptr) : PDU(ETHERTYPE_IP) {

}

Tins::ManagementFrame::ManagementFrame() : IEEE802_11() {
    this->type(IEEE802_11::MANAGEMENT);
}

Tins::ManagementFrame::ManagementFrame(const std::string& iface,
                                       const uint8_t* dst_hw_addr,
                                       const uint8_t* src_hw_addr) throw (std::runtime_error) : IEEE802_11(iface, dst_hw_addr, src_hw_addr) {
    this->type(IEEE802_11::MANAGEMENT);
}

Tins::IEEE802_11_Beacon::IEEE802_11_Beacon() : ManagementFrame() {
    this->subtype(IEEE802_11::BEACON);
    memset(&_body, 0, sizeof(_body));
}

Tins::IEEE802_11_Beacon::IEEE802_11_Beacon(const std::string& iface,
                                           const uint8_t* dst_hw_addr,
                                           const uint8_t* src_hw_addr) throw (std::runtime_error) : ManagementFrame(iface, dst_hw_addr, src_hw_addr){
    this->subtype(IEEE802_11::BEACON);
    memset(&_body, 0, sizeof(_body));
}

void Tins::IEEE802_11_Beacon::timestamp(uint64_t new_timestamp) {
    this->_body.timestamp = new_timestamp;
}

void Tins::IEEE802_11_Beacon::interval(uint16_t new_interval) {
    this->_body.interval = Utils::net_to_host_s(new_interval);
}

void Tins::IEEE802_11_Beacon::essid(const std::string &new_essid) {
    add_tagged_option(IEEE802_11::SSID, new_essid.size(), (const uint8_t*)new_essid.c_str());
}

void Tins::IEEE802_11_Beacon::rates(const std::list<float> &new_rates) {
    uint8_t *buffer = new uint8_t[new_rates.size()], *ptr = buffer;
    for(std::list<float>::const_iterator it = new_rates.begin(); it != new_rates.end(); ++it) {
        uint8_t result = 0x80, left = *it / 0.5;
        if(*it - left > 0) //arbitrary value
            left++;
        *(ptr++) = (result | left);
    }
    add_tagged_option(SUPPORTED_RATES, new_rates.size(), buffer);
    delete[] buffer;
}

void Tins::IEEE802_11_Beacon::channel(uint8_t new_channel) {
    add_tagged_option(DS_SET, 1, &new_channel);
}

uint32_t Tins::IEEE802_11_Beacon::header_size() const {
    return IEEE802_11::header_size() + sizeof(BeaconBody);
}

uint32_t Tins::IEEE802_11_Beacon::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(BeaconBody);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

