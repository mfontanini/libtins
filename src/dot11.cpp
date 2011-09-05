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
#include <algorithm>
#include <utility>
#ifndef WIN32
    #include <net/ethernet.h>
    #include <netpacket/packet.h>
    #include <netinet/in.h>
#endif
#include "dot11.h"
#include "rawpdu.h"
#include "radiotap.h"
#include "sniffer.h"
#include "utils.h"
#include "snap.h"

using namespace std;

const uint8_t *Tins::Dot11::BROADCAST = (const uint8_t*)"\xff\xff\xff\xff\xff\xff";

Tins::Dot11::Dot11(const uint8_t* dst_hw_addr, PDU* child) : PDU(ETHERTYPE_IP, child), _options_size(0) {
    memset(&this->_header, 0, sizeof(ieee80211_header));
    if(dst_hw_addr)
        this->addr1(dst_hw_addr);
}

Tins::Dot11::Dot11(const std::string& iface, const uint8_t* dst_hw_addr, PDU* child) throw (std::runtime_error) : PDU(ETHERTYPE_IP, child), _options_size(0) {
    memset(&this->_header, 0, sizeof(ieee80211_header));
    if(dst_hw_addr)
        this->addr1(dst_hw_addr);
    this->iface(iface);
}


Tins::Dot11::Dot11(uint32_t iface_index, const uint8_t* dst_hw_addr, PDU* child) : PDU(ETHERTYPE_IP, child), _options_size(0) {
    memset(&this->_header, 0, sizeof(ieee80211_header));
    if(dst_hw_addr)
        this->addr1(dst_hw_addr);
    this->iface(iface_index);
}

Tins::Dot11::Dot11(const ieee80211_header *header_ptr) : PDU(ETHERTYPE_IP) {

}

Tins::Dot11::Dot11(const uint8_t *buffer, uint32_t total_sz) : PDU(ETHERTYPE_IP), _options_size(0) {
    if(total_sz < sizeof(_header.control))
        throw std::runtime_error("Not enough size for an IEEE 802.11 header in the buffer.");
    uint32_t sz = std::min((uint32_t)sizeof(_header), total_sz);
    std::memcpy(&_header, buffer, sz);
    buffer += sz;
    total_sz -= sz;
    if(type() == 2 && subtype() < 4) {
        // It's a data packet
        inner_pdu(new Tins::SNAP(buffer, total_sz));
    }
}

Tins::Dot11::Dot11(const Dot11 &other) : PDU(other) {
    copy_80211_fields(&other);
}

Tins::Dot11::~Dot11() {
    while(_options.size()) {
        delete[] _options.front().value;
        _options.pop_front();
    }
}

Tins::Dot11 &Tins::Dot11::operator= (const Dot11 &other) {
    copy_80211_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

void Tins::Dot11::parse_tagged_parameters(const uint8_t *buffer, uint32_t total_sz) {
    uint8_t opcode, length;
    while(total_sz >= 2) {
        opcode = buffer[0];
        length = buffer[1];
        buffer += 2;
        total_sz -= 2;
        if(length > total_sz)
            return; //malformed
        add_tagged_option((TaggedOption)opcode, length, buffer);
        buffer += length;
        total_sz -= length;
    }
}

Tins::Dot11::Dot11_Option::Dot11_Option(uint8_t opt, uint8_t len, const uint8_t *val) : option(opt), length(len) {
    value = new uint8_t[len];
    std::memcpy(value, val, len);
}

void Tins::Dot11::add_tagged_option(TaggedOption opt, uint8_t len, const uint8_t *val) {
    uint32_t opt_size = len + (sizeof(uint8_t) << 1);
    _options.push_back(Dot11_Option((uint8_t)opt, len, val));
    _options_size += opt_size;
}

const Tins::Dot11::Dot11_Option *Tins::Dot11::lookup_option(TaggedOption opt) const {
    for(std::list<Dot11_Option>::const_iterator it = _options.begin(); it != _options.end(); ++it)
        if(it->option == (uint8_t)opt)
            return &(*it);
    return 0;
}

void Tins::Dot11::protocol(uint8_t new_proto) {
    this->_header.control.protocol = new_proto;
}

void Tins::Dot11::type(uint8_t new_type) {
    this->_header.control.type = new_type;
}

void Tins::Dot11::subtype(uint8_t new_subtype) {
    this->_header.control.subtype = new_subtype;
}

void Tins::Dot11::to_ds(bool new_value) {
    this->_header.control.to_ds = (new_value)? 1 : 0;
}

void Tins::Dot11::from_ds(bool new_value) {
    this->_header.control.from_ds = (new_value)? 1 : 0;
}

void Tins::Dot11::more_frag(bool new_value) {
    this->_header.control.more_frag = (new_value)? 1 : 0;
}

void Tins::Dot11::retry(bool new_value) {
    this->_header.control.retry = (new_value)? 1 : 0;
}

void Tins::Dot11::power_mgmt(bool new_value) {
    this->_header.control.power_mgmt = (new_value)? 1 : 0;
}

void Tins::Dot11::wep(bool new_value) {
    this->_header.control.wep = (new_value)? 1 : 0;
}

void Tins::Dot11::order(bool new_value) {
    this->_header.control.order = (new_value)? 1 : 0;
}

void Tins::Dot11::duration_id(uint16_t new_duration_id) {
    this->_header.duration_id = Utils::net_to_host_s(new_duration_id);
}

void Tins::Dot11::addr1(const uint8_t* new_addr1) {
    memcpy(this->_header.addr1, new_addr1, 6);
}

void Tins::Dot11::iface(uint32_t new_iface_index) {
    this->_iface_index = new_iface_index;
}

void Tins::Dot11::iface(const std::string& new_iface) throw (std::runtime_error) {
    if (!Tins::Utils::interface_id(new_iface, this->_iface_index)) {
        throw std::runtime_error("Invalid interface name!");
    }
}

uint32_t Tins::Dot11::header_size() const {
    uint32_t sz = sizeof(ieee80211_header) + _options_size;
    return sz;
}

bool Tins::Dot11::send(PacketSender* sender) {
    struct sockaddr_ll addr;

    memset(&addr, 0, sizeof(struct sockaddr_ll));

    addr.sll_family = Utils::net_to_host_s(PF_PACKET);
    addr.sll_protocol = Utils::net_to_host_s(ETH_P_ALL);
    addr.sll_halen = 6;
    addr.sll_ifindex = this->_iface_index;
    memcpy(&(addr.sll_addr), this->_header.addr1, 6);

    return sender->send_l2(this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
}

void Tins::Dot11::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    uint32_t my_sz = header_size();
    assert(total_sz >= my_sz);
    memcpy(buffer, &this->_header, sizeof(ieee80211_header));
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);

    uint32_t written = this->write_ext_header(buffer, total_sz);
    buffer += written;
    total_sz -= written;

    uint32_t child_len = write_fixed_parameters(buffer, total_sz - sizeof(ieee80211_header) - _options_size);
    buffer += child_len;
    assert(total_sz > child_len + _options_size);
    for(std::list<Dot11_Option>::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        *(buffer++) = it->option;
        *(buffer++) = it->length;
        std::memcpy(buffer, it->value, it->length);
        buffer += it->length;
    }
}

Tins::PDU *Tins::Dot11::from_bytes(const uint8_t *buffer, uint32_t total_sz) {
    // We only need the control field, the length of the PDU will depend on the flags set.
    if(total_sz < sizeof(ieee80211_header::control))
        throw std::runtime_error("Not enough size for a IEEE 802.11 header in the buffer.");
    const ieee80211_header *hdr = (const ieee80211_header*)buffer;
    PDU *ret = 0;
    if(hdr->control.type == 0 && hdr->control.subtype == 8) {
        if(total_sz < sizeof(_header))
            throw std::runtime_error("Not enough size for an IEEE 802.11 header in the buffer.");
        ret = new Dot11Beacon(buffer, total_sz);
    }
    else
        ret = new Dot11(buffer, total_sz);
    return ret;
}

void Tins::Dot11::copy_80211_fields(const Dot11 *other) {
    std::memcpy(&_header, &other->_header, sizeof(_header));
    _iface_index = other->_iface_index;
    _options_size = other->_options_size;
    for(std::list<Dot11_Option>::const_iterator it = other->_options.begin(); it != other->_options.end(); ++it)
        _options.push_back(Dot11_Option(it->option, it->length, it->value));
}

/*
 * Dot11ManagementFrame
 */

Tins::Dot11ManagementFrame::Dot11ManagementFrame(const uint8_t *buffer, uint32_t total_sz) : Dot11(buffer, total_sz) {

}

Tins::Dot11ManagementFrame::Dot11ManagementFrame(const uint8_t *dst_hw_addr, const uint8_t *src_hw_addr) : Dot11(dst_hw_addr) {
    this->type(Dot11::MANAGEMENT);
    this->addr2(src_hw_addr);
}

Tins::Dot11ManagementFrame::Dot11ManagementFrame(const std::string &iface,
                                       const uint8_t *dst_hw_addr,
                                       const uint8_t *src_hw_addr) throw (std::runtime_error) : Dot11(iface, dst_hw_addr) {
    this->type(Dot11::MANAGEMENT);
    this->addr2(src_hw_addr);
}

Tins::Dot11ManagementFrame::Dot11ManagementFrame(const Dot11ManagementFrame &other) : Dot11(other) {

}

void Tins::Dot11ManagementFrame::copy_ext_header(const Dot11ManagementFrame* other) {
    Dot11::copy_80211_fields(other);
    std::memcpy(&this->_ext_header, &other->_ext_header, sizeof(this->_ext_header));
    std::memcpy(this->_addr4, other->_addr4, 6);
}

uint32_t Tins::Dot11ManagementFrame::header_size() const {
    uint32_t sz = Dot11::header_size() + sizeof(_ext_header);
    if (this->from_ds() && this->to_ds())
        sz += 6;
    return sz;
}

void Tins::Dot11ManagementFrame::addr2(const uint8_t* new_addr2) {
    memcpy(this->_ext_header.addr2, new_addr2, 6);
}

void Tins::Dot11ManagementFrame::addr3(const uint8_t* new_addr3) {
    memcpy(this->_ext_header.addr3, new_addr3, 6);
}

void Tins::Dot11ManagementFrame::frag_num(uint8_t new_frag_num) {
    this->_ext_header.seq_control.frag_number = new_frag_num;
}

void Tins::Dot11ManagementFrame::seq_num(uint16_t new_seq_num) {
    this->_ext_header.seq_control.seq_number = Utils::net_to_host_s(new_seq_num);
}

void Tins::Dot11ManagementFrame::addr4(const uint8_t* new_addr4) {
    memcpy(this->_addr4, new_addr4, 6);
}

uint32_t Tins::Dot11ManagementFrame::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    uint32_t written = sizeof(this->_ext_header);
    memcpy(buffer, &this->_ext_header, sizeof(this->_ext_header));
    buffer += sizeof(this->_ext_header);
    if (this->from_ds() && this->to_ds()) {
        written += 6;
        memcpy(buffer, this->_addr4, 6);
    }
    return written;

}

void Tins::Dot11ManagementFrame::ssid(const std::string &new_ssid) {
    add_tagged_option(Dot11::SSID, new_ssid.size(), (const uint8_t*)new_ssid.c_str());
}

void Tins::Dot11ManagementFrame::rates(const std::list<float> &new_rates) {
    uint8_t *buffer = new uint8_t[new_rates.size()], *ptr = buffer;
    for(std::list<float>::const_iterator it = new_rates.begin(); it != new_rates.end(); ++it) {
        uint8_t result = 0x80, left = *it / 0.5;
        if(*it - left > 0)
            left++;
        *(ptr++) = (result | left);
    }
    add_tagged_option(SUPPORTED_RATES, new_rates.size(), buffer);
    delete[] buffer;
}

void Tins::Dot11ManagementFrame::channel(uint8_t new_channel) {
    add_tagged_option(DS_SET, 1, &new_channel);
}

void Tins::Dot11ManagementFrame::rsn_information(const RSNInformation& info) {
    uint32_t size;
    uint8_t *buffer = info.serialize(size);
    add_tagged_option(RSN, size, buffer);
    delete[] buffer;
}

void Tins::Dot11ManagementFrame::supported_rates(const std::list<float> &new_rates) {
    uint8_t *buffer = new uint8_t[new_rates.size()], *ptr = buffer;
    for(std::list<float>::const_iterator it = new_rates.begin(); it != new_rates.end(); ++it) {
        uint8_t result = 0x80, left = *it / 0.5;
        if(*it - left > 0)
            left++;
        *(ptr++) = (result | left);
    }
    add_tagged_option(SUPPORTED_RATES, new_rates.size(), buffer);
    delete[] buffer;
}

void Tins::Dot11ManagementFrame::extended_supported_rates(const std::list<float> &new_rates) {
    uint8_t *buffer = new uint8_t[new_rates.size()], *ptr = buffer;
    for(std::list<float>::const_iterator it = new_rates.begin(); it != new_rates.end(); ++it) {
        uint8_t result = 0x80, left = *it / 0.5;
        if(*it - left > 0)
            left++;
        *(ptr++) = (result | left);
    }
    add_tagged_option(EXT_SUPPORTED_RATES, new_rates.size(), buffer);
    delete[] buffer;
}

void Tins::Dot11ManagementFrame::qos_capabilities(uint8_t new_qos_capabilities) {
    add_tagged_option(QOS_CAPABILITY, 1, &new_qos_capabilities);
}

void Tins::Dot11ManagementFrame::power_capabilities(uint8_t min_power, uint8_t max_power) {
    uint8_t buffer[2];
    buffer[0] = min_power;
    buffer[1] = max_power;
    add_tagged_option(POWER_CAPABILITY, 2, buffer);
}

void Tins::Dot11ManagementFrame::supported_channels(const std::list<std::pair<uint8_t, uint8_t> > &new_channels) {
    uint8_t* buffer = new uint8_t[new_channels.size() * 2];
    uint8_t* ptr = buffer;
    for(std::list<pair<uint8_t, uint8_t> >::const_iterator it = new_channels.begin(); it != new_channels.end(); ++it) {
        *(ptr++) = it->first;
        *(ptr++) = it->second;
    }
    add_tagged_option(SUPPORTED_CHANNELS, new_channels.size() * 2, buffer);
    delete[] buffer;
}

void Tins::Dot11ManagementFrame::edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo) {
    uint8_t* buffer = new uint8_t[18];
    buffer[0] = 0;
    uint32_t* ptr = (uint32_t*)(buffer + 1);
    *(ptr++) = ac_be;
    *(ptr++) = ac_bk;
    *(ptr++) = ac_vi;
    *(ptr++) = ac_vo;
    add_tagged_option(EDCA, 18, buffer);
    delete[] buffer;
}

/*
 * Dot11DataFrame
 */

Tins::Dot11DataFrame::Dot11DataFrame(const uint8_t *buffer, uint32_t total_sz) : Dot11(buffer, total_sz) {

}

Tins::Dot11DataFrame::Dot11DataFrame(uint32_t iface_index, const uint8_t *dst_hw_addr, const uint8_t *src_hw_addr, PDU* child) : Dot11(iface_index, dst_hw_addr, child) {
    this->type(Dot11::DATA);
    this->addr2(src_hw_addr);
}

Tins::Dot11DataFrame::Dot11DataFrame(const uint8_t *dst_hw_addr, const uint8_t *src_hw_addr, PDU* child) : Dot11(dst_hw_addr, child) {
    this->type(Dot11::DATA);
    this->addr2(src_hw_addr);
}


Tins::Dot11DataFrame::Dot11DataFrame(const std::string &iface,
                                     const uint8_t *dst_hw_addr,
                                     const uint8_t *src_hw_addr,
                                     PDU* child) throw (std::runtime_error) : Dot11(iface, dst_hw_addr, child) {
    this->type(Dot11::DATA);
    this->addr2(src_hw_addr);
}

Tins::Dot11DataFrame::Dot11DataFrame(const Dot11DataFrame &other) : Dot11(other) {

}

void Tins::Dot11DataFrame::copy_ext_header(const Dot11DataFrame* other) {
    Dot11::copy_80211_fields(other);
    std::memcpy(&this->_ext_header, &other->_ext_header, sizeof(this->_ext_header));
    std::memcpy(this->_addr4, other->_addr4, 6);
}

uint32_t Tins::Dot11DataFrame::header_size() const {
    uint32_t sz = Dot11::header_size() + sizeof(_ext_header);
    if (this->from_ds() && this->to_ds())
        sz += 6;
    return sz;
}

void Tins::Dot11DataFrame::addr2(const uint8_t* new_addr2) {
    memcpy(this->_ext_header.addr2, new_addr2, 6);
}

void Tins::Dot11DataFrame::addr3(const uint8_t* new_addr3) {
    memcpy(this->_ext_header.addr3, new_addr3, 6);
}

void Tins::Dot11DataFrame::frag_num(uint8_t new_frag_num) {
    this->_ext_header.seq_control.frag_number = new_frag_num;
}

void Tins::Dot11DataFrame::seq_num(uint16_t new_seq_num) {
    this->_ext_header.seq_control.seq_number = Utils::net_to_host_s(new_seq_num);
}

void Tins::Dot11DataFrame::addr4(const uint8_t* new_addr4) {
    memcpy(this->_addr4, new_addr4, 6);
}

uint32_t Tins::Dot11DataFrame::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    uint32_t written = sizeof(this->_ext_header);
    memcpy(buffer, &this->_ext_header, sizeof(this->_ext_header));
    buffer += sizeof(this->_ext_header);
    if (this->from_ds() && this->to_ds()) {
        written += 6;
        memcpy(buffer, this->_addr4, 6);
    }
    return written;

}

/*
 * Beacon
 */

Tins::Dot11Beacon::Dot11Beacon(const uint8_t* dst_hw_addr, const uint8_t* src_hw_addr) : Dot11ManagementFrame() {
    this->subtype(Dot11::BEACON);
    memset(&_body, 0, sizeof(_body));
}

Tins::Dot11Beacon::Dot11Beacon(const std::string& iface,
                                           const uint8_t* dst_hw_addr,
                                           const uint8_t* src_hw_addr) throw (std::runtime_error) : Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr){
    this->subtype(Dot11::BEACON);
    memset(&_body, 0, sizeof(_body));
}

Tins::Dot11Beacon::Dot11Beacon(const uint8_t *buffer, uint32_t total_sz) : Dot11ManagementFrame(buffer, total_sz) {
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);
    if(total_sz < sizeof(_body))
        throw std::runtime_error("Not enough size for a IEEE 802.11 beacon header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

Tins::Dot11Beacon::Dot11Beacon(const Dot11Beacon &other) : Dot11ManagementFrame(other) {

}

Tins::Dot11Beacon &Tins::Dot11Beacon::operator= (const Dot11Beacon &other) {
    copy_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

void Tins::Dot11Beacon::copy_fields(const Dot11Beacon *other) {
    Dot11ManagementFrame::copy_ext_header(other);
    std::memcpy(&_body, &other->_body, sizeof(_body));
}

void Tins::Dot11Beacon::timestamp(uint64_t new_timestamp) {
    this->_body.timestamp = new_timestamp;
}

void Tins::Dot11Beacon::interval(uint16_t new_interval) {
    this->_body.interval = Utils::net_to_host_s(new_interval);
}

void Tins::Dot11Beacon::essid(const std::string &new_essid) {
    Dot11ManagementFrame::ssid(new_essid);
}

void Tins::Dot11Beacon::rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::rates(new_rates);
}

void Tins::Dot11Beacon::channel(uint8_t new_channel) {
    Dot11ManagementFrame::channel(new_channel);
}

void Tins::Dot11Beacon::rsn_information(const RSNInformation& info) {
    Dot11ManagementFrame::rsn_information(info);
}

string Tins::Dot11Beacon::essid() const {
    const Dot11::Dot11_Option *option = lookup_option(SSID);
    return (option) ? string((const char*)option->value, option->length) : 0;
}

bool Tins::Dot11Beacon::rsn_information(RSNInformation *rsn) {
    const Dot11::Dot11_Option *option = lookup_option(RSN);
    if(!option || option->length < (sizeof(uint16_t) << 1) + sizeof(uint32_t))
        return false;
    const uint8_t *buffer = option->value;
    uint32_t bytes_left = option->length;
    rsn->version(*(uint16_t*)buffer);
    buffer += sizeof(uint16_t);
    rsn->group_suite((RSNInformation::CypherSuites)*(uint32_t*)buffer);
    buffer += sizeof(uint32_t);

    bytes_left -= (sizeof(uint16_t) << 1) + sizeof(uint32_t);
    if(bytes_left < sizeof(uint16_t))
        return false;
    uint16_t count = *(uint16_t*)buffer;
    buffer += sizeof(uint16_t);
    if(count * sizeof(uint32_t) > bytes_left)
        return false;
    bytes_left -= count * sizeof(uint32_t);
    while(count--) {
        rsn->add_pairwise_cypher((RSNInformation::CypherSuites)*(uint32_t*)buffer);
        buffer += sizeof(uint32_t);
    }
    if(bytes_left < sizeof(uint16_t))
        return false;
    count = *(uint16_t*)buffer;
    buffer += sizeof(uint16_t);
    bytes_left -= sizeof(uint16_t);
    if(count * sizeof(uint32_t) > bytes_left)
        return false;
    bytes_left -= count * sizeof(uint32_t);
    while(count--) {
        rsn->add_akm_cypher((RSNInformation::AKMSuites)*(uint32_t*)buffer);
        buffer += sizeof(uint32_t);
    }
    if(bytes_left < sizeof(uint16_t))
        return false;
    rsn->capabilities(*(uint16_t*)buffer);
    return true;
}

uint32_t Tins::Dot11Beacon::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(BeaconBody);
}

uint32_t Tins::Dot11Beacon::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(BeaconBody);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* 802.11 diassoc */

Tins::Dot11Disassoc::Dot11Disassoc() : Dot11ManagementFrame() {
    this->subtype(Dot11::DISASSOC);
    memset(&_body, 0, sizeof(_body));
}

Tins::Dot11Disassoc::Dot11Disassoc(const std::string& iface,
                                           const uint8_t* dst_hw_addr,
                                           const uint8_t* src_hw_addr) throw (std::runtime_error) : Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr){
    this->subtype(Dot11::DISASSOC);
    memset(&_body, 0, sizeof(_body));
}

Tins::Dot11Disassoc::Dot11Disassoc(const Dot11Disassoc &other) : Dot11ManagementFrame(other) {
    copy_fields(&other);
}

Tins::Dot11Disassoc &Tins::Dot11Disassoc::operator= (const Dot11Disassoc &other) {
    copy_inner_pdu(other);
    copy_fields(&other);
    return *this;
}

void Tins::Dot11Disassoc::copy_fields(const Dot11Disassoc *other) {
    Dot11ManagementFrame::copy_ext_header(other);
    std::memcpy(&_body, &other->_body, sizeof(_body));
}

void Tins::Dot11Disassoc::reason_code(uint16_t new_reason_code) {
    this->_body.reason_code = new_reason_code;
}

uint32_t Tins::Dot11Disassoc::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(DisassocBody);
}

uint32_t Tins::Dot11Disassoc::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(DisassocBody);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/*
 * RSNInformation class
 */
Tins::RSNInformation::RSNInformation() : _version(1), _capabilities(0) {

}

void Tins::RSNInformation::add_pairwise_cypher(CypherSuites cypher) {
    _pairwise_cyphers.push_back(cypher);
}

void Tins::RSNInformation::add_akm_cypher(AKMSuites akm) {
    _akm_cyphers.push_back(akm);
}

void Tins::RSNInformation::group_suite(CypherSuites group) {
    _group_suite = group;
}

void Tins::RSNInformation::version(uint16_t ver) {
    _version = ver;
}

void Tins::RSNInformation::capabilities(uint16_t cap) {
    _capabilities = cap;
}

uint8_t *Tins::RSNInformation::serialize(uint32_t &size) const {
    size = sizeof(_version) + sizeof(_capabilities) + sizeof(uint32_t);
    size += (sizeof(uint16_t) << 1); // 2 lists count.
    size += sizeof(uint32_t) * (_akm_cyphers.size() + _pairwise_cyphers.size());

    uint8_t *buffer = new uint8_t[size], *ptr = buffer;
    *(uint16_t*)ptr = _version;
    ptr += sizeof(_version);
    *(uint32_t*)ptr = _group_suite;
    ptr += sizeof(uint32_t);
    *(uint16_t*)ptr = _pairwise_cyphers.size();
    ptr += sizeof(uint16_t);
    for(std::list<CypherSuites>::const_iterator it = _pairwise_cyphers.begin(); it != _pairwise_cyphers.end(); ++it) {
        *(uint32_t*)ptr = *it;
        ptr += sizeof(uint32_t);
    }
    *(uint16_t*)ptr = _akm_cyphers.size();
    ptr += sizeof(uint16_t);
    for(std::list<AKMSuites>::const_iterator it = _akm_cyphers.begin(); it != _akm_cyphers.end(); ++it) {
        *(uint32_t*)ptr = *it;
        ptr += sizeof(uint32_t);
    }
    *(uint16_t*)ptr = _capabilities;
    return buffer;
}

Tins::RSNInformation Tins::RSNInformation::wpa2_psk() {
    RSNInformation info;
    info.group_suite(RSNInformation::CCMP);
    info.add_pairwise_cypher(RSNInformation::CCMP);
    info.add_akm_cypher(RSNInformation::PSK);
    return info;
}

/* Assoc request. */

Tins::Dot11AssocRequest::Dot11AssocRequest() : Dot11ManagementFrame() {
    this->subtype(Dot11::ASSOC_REQ);
    memset(&_body, 0, sizeof(_body));
}

Tins::Dot11AssocRequest::Dot11AssocRequest(const std::string& iface,
                                           const uint8_t* dst_hw_addr,
                                           const uint8_t* src_hw_addr) throw (std::runtime_error) : Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr){
    this->subtype(Dot11::ASSOC_REQ);
    memset(&_body, 0, sizeof(_body));
}

Tins::Dot11AssocRequest::Dot11AssocRequest(const uint8_t *buffer, uint32_t total_sz) : Dot11ManagementFrame(buffer, total_sz) {
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);
    if(total_sz < sizeof(_body))
        throw std::runtime_error("Not enough size for an IEEE 802.11 association header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

Tins::Dot11AssocRequest::Dot11AssocRequest(const Dot11AssocRequest &other) : Dot11ManagementFrame(other) {
    copy_fields(&other);
}

Tins::Dot11AssocRequest &Tins::Dot11AssocRequest::operator= (const Dot11AssocRequest &other) {
    copy_inner_pdu(other);
    copy_fields(&other);
    return *this;
}

void Tins::Dot11AssocRequest::copy_fields(const Dot11AssocRequest *other) {
    Dot11ManagementFrame::copy_ext_header(other);
    std::memcpy(&_body, &other->_body, sizeof(_body));
}

void Tins::Dot11AssocRequest::listen_interval(uint16_t new_listen_interval) {
    this->_body.listen_interval = new_listen_interval;
}

void Tins::Dot11AssocRequest::ssid(const std::string &new_ssid) {
    Dot11ManagementFrame::ssid(new_ssid);
}

void Tins::Dot11AssocRequest::supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::supported_rates(new_rates);
}

void Tins::Dot11AssocRequest::extended_supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::extended_supported_rates(new_rates);
}

void Tins::Dot11AssocRequest::power_capabilities(uint8_t min_power, uint8_t max_power) {
    Dot11ManagementFrame::power_capabilities(min_power, max_power);
}

void Tins::Dot11AssocRequest::supported_channels(const std::list<pair<uint8_t, uint8_t> > &new_channels) {
    Dot11ManagementFrame::supported_channels(new_channels);
}

void Tins::Dot11AssocRequest::rsn_information(const RSNInformation& info) {
    Dot11ManagementFrame::rsn_information(info);
}

void Tins::Dot11AssocRequest::qos_capabilities(uint8_t new_qos_capabilities) {
    Dot11ManagementFrame::qos_capabilities(new_qos_capabilities);
}

uint32_t Tins::Dot11AssocRequest::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(AssocReqBody);
}

uint32_t Tins::Dot11AssocRequest::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(AssocReqBody);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* Assoc response. */

Tins::Dot11AssocResponse::Dot11AssocResponse() : Dot11ManagementFrame() {
    this->subtype(Dot11::ASSOC_RESP);
    memset(&_body, 0, sizeof(_body));
}

Tins::Dot11AssocResponse::Dot11AssocResponse(const std::string& iface,
                                                           const uint8_t* dst_hw_addr,
                                                           const uint8_t* src_hw_addr) throw (std::runtime_error) : Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr) {
    this->subtype(Dot11::ASSOC_RESP);
    memset(&_body, 0, sizeof(_body));
}

Tins::Dot11AssocResponse::Dot11AssocResponse(const uint8_t *buffer, uint32_t total_sz) : Dot11ManagementFrame(buffer, total_sz) {
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);
    if(total_sz < sizeof(_body))
        throw std::runtime_error("Not enough size for an IEEE 802.11 association response header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

Tins::Dot11AssocResponse::Dot11AssocResponse(const Dot11AssocResponse &other) : Dot11ManagementFrame(other) {
    copy_fields(&other);
}

Tins::Dot11AssocResponse &Tins::Dot11AssocResponse::operator= (const Dot11AssocResponse &other) {
    copy_inner_pdu(other);
    copy_fields(&other);
    return *this;
}

void Tins::Dot11AssocResponse::copy_fields(const Dot11AssocResponse *other) {
    Dot11ManagementFrame::copy_ext_header(other);
    std::memcpy(&_body, &other->_body, sizeof(_body));
}

void Tins::Dot11AssocResponse::status_code(uint16_t new_status_code) {
    this->_body.status_code = new_status_code;
}

void Tins::Dot11AssocResponse::aid(uint16_t new_aid) {
    this->_body.aid = new_aid;
}

void Tins::Dot11AssocResponse::supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::supported_rates(new_rates);
}

void Tins::Dot11AssocResponse::extended_supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::extended_supported_rates(new_rates);
}

void Tins::Dot11AssocResponse::edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo) {
    Dot11ManagementFrame::edca_parameter_set(ac_be, ac_bk, ac_vi, ac_vo);
}

uint32_t Tins::Dot11AssocResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(AssocRespBody);
}

uint32_t Tins::Dot11AssocResponse::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(AssocRespBody);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* QoS data. */

Tins::Dot11QoSData::Dot11QoSData(const std::string& iface, const uint8_t* dst_hw_addr, const uint8_t* src_hw_addr, PDU* child) throw (std::runtime_error) : Dot11DataFrame(iface, dst_hw_addr, src_hw_addr, child) {
    this->subtype(Dot11::QOS_DATA_DATA);
    this->_qos_control = 0;
}

Tins::Dot11QoSData::Dot11QoSData(uint32_t iface_index, const uint8_t* dst_hw_addr, const uint8_t* src_hw_addr, PDU* child) : Dot11DataFrame(iface_index, dst_hw_addr, src_hw_addr, child) {
    this->subtype(Dot11::QOS_DATA_DATA);
    this->_qos_control = 0;
}

Tins::Dot11QoSData::Dot11QoSData(const uint8_t *buffer, uint32_t total_sz) : Dot11DataFrame(buffer, total_sz) {
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);
    assert(total_sz >= sizeof(this->_qos_control));
    this->_qos_control = *(uint16_t*)buffer;
    total_sz -= sizeof(uint16_t);
    buffer += sizeof(uint16_t);
    if(total_sz)
        inner_pdu(new Tins::SNAP(buffer, total_sz));
}

Tins::Dot11QoSData::Dot11QoSData(const Dot11QoSData &other) : Dot11DataFrame(other) {
    copy_fields(&other);
}

Tins::Dot11QoSData &Tins::Dot11QoSData::operator= (const Dot11QoSData &other) {
    copy_inner_pdu(other);
    copy_fields(&other);
    return *this;
}

void Tins::Dot11QoSData::copy_fields(const Dot11QoSData *other) {
    Dot11DataFrame::copy_ext_header(other);
    _qos_control = other->_qos_control;
}

void Tins::Dot11QoSData::qos_control(uint16_t new_qos_control) {
    this->_qos_control = new_qos_control;
}

uint32_t Tins::Dot11QoSData::header_size() const {
    return Dot11::header_size() + sizeof(this->_qos_control);
}

uint32_t Tins::Dot11QoSData::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_qos_control);
    assert(sz <= total_sz);
    *(uint16_t*)buffer = this->_qos_control;
    return sz;
}

/* Dot11Control */
Tins::Dot11Control::Dot11Control(const uint8_t* dst_addr, PDU* child) : Dot11(dst_addr, child) {
    type(CONTROL);
}

Tins::Dot11ControlTA::Dot11ControlTA(const std::string& iface, const uint8_t* dst_addr, PDU* child) throw (std::runtime_error) : Dot11(iface, dst_addr, child) {
    type(CONTROL);
}

Tins::Dot11ControlTA::Dot11ControlTA(uint32_t iface_index, const uint8_t* dst_addr, PDU* child) : Dot11(iface_index, dst_addr, child) {
    type(CONTROL);
}

Tins::Dot11ControlTA::Dot11ControlTA(const uint8_t *buffer, uint32_t total_sz) : Dot11(buffer, total_sz) {

}

/* Dot11ControlTA */
Tins::Dot11ControlTA::Dot11ControlTA(const uint8_t* dst_addr, const uint8_t *target_addres, PDU* child) : Dot11Control(dst_addr, child) {
    if(target_addr)
        target_addr(target_address);
    else
        std::memset(_taddr, 0, sizeof(_taddr));
}

Tins::Dot11ControlTA::Dot11ControlTA(const std::string& iface, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child) throw (std::runtime_error) : Dot11Control(iface, dst_addr, child){
    if(target_addr)
        target_addr(target_address);
    else
        std::memset(_taddr, 0, sizeof(_taddr));
}

Tins::Dot11ControlTA::Dot11ControlTA(uint32_t iface_index, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child) : Dot11Control(iface_index, dst_addr, child) {
    if(target_addr)
        target_addr(target_address);
    else
        std::memset(_taddr, 0, sizeof(_taddr));
}

Tins::Dot11ControlTA::Dot11ControlTA(const uint8_t *buffer, uint32_t total_sz) : Dot11Control(buffer, total_sz) {
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);
    if(total_sz < sizeof(_taddr))
        throw std::runtime_error("Not enough size for an IEEE 802.11 RTS frame in the buffer.");
    std::memcpy(_taddr, buffer, sizeof(_taddr));
}

uint32_t Tins::Dot11ControlTA::header_size() const {
    return Dot11::header_size() + sizeof(_taddr);
}

uint32_t Tins::Dot11ControlTA::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    assert(total_sz >= sizeof(_taddr));
    std::memcpy(buffer, _taddr, sizeof(_taddr));
    return sizeof(_taddr);
}

void Tins::Dot11ControlTA::target_addr(const uint8_t *addr) {
    std::memcpy(_taddr, addr, sizeof(_taddr));
}

/* Dot11RTS */
Tins::Dot11RTS::Dot11RTS(const uint8_t* dst_addr , const uint8_t* target_addr, PDU* child) :  Dot11ControlTA(dst_addr, target_addr, child) {
    subtype(RTS);
}

Tins::Dot11RTS::Dot11RTS(const std::string& iface, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child) throw (std::runtime_error) : Dot11ControlTA(iface, dst_addr, target_addr, child) { 
    subtype(RTS);
}

Tins::Dot11RTS::Dot11RTS(uint32_t iface_index, const uint8_t* dst_hw_addr, const uint8_t *target_addr, PDU* child) : Dot11ControlTA(iface_index, dst_addr, target_addr, child) { 
    subtype(RTS);
}

Tins::Dot11RTS::Dot11RTS(const uint8_t *buffer, uint32_t total_sz) : Dot11ControlTA(buffer, total_sz) { 
    
}

/* Dot11PSPoll */
Tins::Dot11PSPoll::Dot11PSPoll(const uint8_t* dst_addr , const uint8_t* target_addr, PDU* child) :  Dot11ControlTA(dst_addr, target_addr, child) {
    subtype(PS);
}

Tins::Dot11PSPoll::Dot11PSPoll(const std::string& iface, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child) throw (std::runtime_error) : Dot11ControlTA(iface, dst_addr, target_addr, child) { 
    subtype(PS);
}

Tins::Dot11PSPoll::Dot11PSPoll(uint32_t iface_index, const uint8_t* dst_hw_addr, const uint8_t *target_addr, PDU* child) : Dot11ControlTA(iface_index, dst_addr, target_addr, child) { 
    subtype(PS);
}

Tins::Dot11PSPoll::Dot11PSPoll(const uint8_t *buffer, uint32_t total_sz) : Dot11ControlTA(buffer, total_sz) { 
    
}

/* Dot11CFEnd */

Tins::Dot11CFEnd::Dot11CFEnd(const uint8_t* dst_addr , const uint8_t* target_addr, PDU* child) :  Dot11ControlTA(dst_addr, target_addr, child) {
    subtype(CF_END);
}

Tins::Dot11CFEnd::Dot11CFEnd(const std::string& iface, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child) throw (std::runtime_error) : Dot11ControlTA(iface, dst_addr, target_addr, child) { 
    subtype(CF_END);
}

Tins::Dot11CFEnd::Dot11CFEnd(uint32_t iface_index, const uint8_t* dst_hw_addr, const uint8_t *target_addr, PDU* child) : Dot11ControlTA(iface_index, dst_addr, target_addr, child) { 
    subtype(CF_END);
}

Tins::Dot11CFEnd::Dot11CFEnd(const uint8_t *buffer, uint32_t total_sz) : Dot11ControlTA(buffer, total_sz) { 
    
}

/* Dot11EndCFAck */

Tins::Dot11EndCFAck::Dot11EndCFAck(const uint8_t* dst_addr , const uint8_t* target_addr, PDU* child) :  Dot11ControlTA(dst_addr, target_addr, child) {
    subtype(CF_END_ACK);
}

Tins::Dot11EndCFAck::Dot11EndCFAck(const std::string& iface, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child) throw (std::runtime_error) : Dot11ControlTA(iface, dst_addr, target_addr, child) { 
    subtype(CF_END_ACK);
}

Tins::Dot11EndCFAck::Dot11EndCFAck(uint32_t iface_index, const uint8_t* dst_hw_addr, const uint8_t *target_addr, PDU* child) : Dot11ControlTA(iface_index, dst_addr, target_addr, child) { 
    subtype(CF_END_ACK);
}

Tins::Dot11EndCFAck::Dot11EndCFAck(const uint8_t *buffer, uint32_t total_sz) : Dot11ControlTA(buffer, total_sz) { 
    
}

/* Dot11Ack */

Tins::Dot11Ack::Dot11Ack(const uint8_t* dst_addr , PDU* child) :  Dot11(dst_addr, target_addr, child) {
    subtype(ACK);
}

Tins::Dot11Ack::Dot11Ack(const std::string& iface, onst uint8_t *target_addr, PDU* child) throw (std::runtime_error) : Dot11(iface, dst_addr, child) { 
    subtype(ACK);
}

Tins::Dot11Ack::Dot11Ack(uint32_t iface_index, const uint8_t* dst_hw_addr, PDU* child) : Dot11(iface_index, dst_addr, child) { 
    subtype(ACK);
}

Tins::Dot11Ack::Dot11Ack(const uint8_t *buffer, uint32_t total_sz) : Dot11(buffer, total_sz) { 
    
}

/* Dot11BlockAck */

Tins::Dot11BlockAckRequest::Dot11BlockAckRequest(const uint8_t* dst_addr , const uint8_t* target_addr, PDU* child) :  Dot11ControlTA(dst_addr, target_addr, child) {
    init_block_ack();
}

Tins::Dot11BlockAckRequest::Dot11BlockAckRequest(const std::string& iface, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child) throw (std::runtime_error) : Dot11ControlTA(iface, dst_addr, target_addr, child) { 
    init_block_ack();
}

Tins::Dot11BlockAckRequest::Dot11BlockAckRequest(uint32_t iface_index, const uint8_t* dst_hw_addr, const uint8_t *target_addr, PDU* child) : Dot11ControlTA(iface_index, dst_addr, target_addr, child) { 
    init_block_ack();
}

Tins::Dot11BlockAckRequest::Dot11BlockAckRequest(const uint8_t *buffer, uint32_t total_sz) : Dot11ControlTA(buffer, total_sz) { 
    uint32_t padding = controlta_size();
    buffer += padding;
    total_sz -= padding;
    if(total_sz < sizeof(_bar_control) + sizeof(_start_sequence))
        throw std::runtime_error("Not enough size for an IEEE 802.11 Block Ack frame in the buffer.");
    std::memcpy(&_bar_control, buffer, sizeof(_bar_control));
    buffer += sizeof(_bar_control);
    std::memcpy(&_start_sequence, buffer, sizeof(_start_sequence));
}

void Tins::Dot11BlockAckRequest::init_block_ack() {
    subtype(BLOCK_ACK);
    std::memset(&_bar_control, 0, sizeof(_bar_control));
    std::memset(&_start_sequence, 0, sizeof(_start_sequence));
}

uint32_t Tins::Dot11BlockAckRequest::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    uint32_t parent_size = Dot11ControlTA::write_ext_header(buffer, total_sz);
    buffer += parent_size;
    std::memcpy(buffer, _bar_control, sizeof(_bar_control));
    buffer += sizeof(_bar_control);
    std::memcpy(buffer, _start_sequence, sizeof(_start_sequence));
    return parent_size + sizeof(_start_sequence);
}

void Tins::Dot11BlockAckRequest::bar_control(uint16_t bar) {
    std::memcpy(&_bar_control, &bar, sizeof(bar));
}
        
void Tins::Dot11BlockAckRequest::start_sequence(uint16_t seq) {
    std::memcpy(&_start_sequence, &seq, sizeof(seq));
}

uint32_t Tins::Dot11BlockAckRequest::header_size() const {
    return Dot11ControlTA::header_size() + sizeof(_start_sequence) + sizeof(_start_sequence);
}

/* Dot11BlockAck */
Tins::Dot11BlockAck::Dot11BlockAck(const uint8_t* dst_addr , const uint8_t* target_addr, PDU* child) :  Dot11BlockAckRequest(dst_addr, target_addr, child) {
    std::memset(_bitmap, 0, sizeof(_bitmap));
}

Tins::Dot11BlockAck::Dot11BlockAck(const std::string& iface, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child) throw (std::runtime_error) : Dot11BlockAckRequest(iface, dst_addr, target_addr, child) { 
    std::memset(_bitmap, 0, sizeof(_bitmap));
}

Tins::Dot11BlockAck::Dot11BlockAck(uint32_t iface_index, const uint8_t* dst_hw_addr, const uint8_t *target_addr, PDU* child) : Dot11BlockAckRequest(iface_index, dst_addr, target_addr, child) { 
    std::memset(_bitmap, 0, sizeof(_bitmap));
}

Tins::Dot11BlockAck::Dot11BlockAck(const uint8_t *buffer, uint32_t total_sz) : Dot11BlockAckRequest(buffer, total_sz) { 
    uint32_t padding = blockack_request_size();
    buffer += padding;
    total_sz -= padding;
    if(total_sz < sizeof(_bitmap))
        throw std::runtime_error("Not enough size for an IEEE 802.11 Block Ack frame in the buffer.");
    std::memcpy(&_bitmap, buffer, sizeof(_bitmap));
}

void Tins::Dot11BlockAck::bitmap(const uint8_t bit) {
    std::memcpy(_bitmap, bit, sizeof(_bitmap));
}

uint32_t Tins::Dot11BlockAck::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    uint32_t parent_size = Dot11BlockAckRequest::write_ext_header(buffer, total_sz);
    buffer += parent_size;
    std::memcpy(buffer, _bitmap, sizeof(_bitmap));
    return parent_size + sizeof(_bitmap);
}

uint32_t Tins::Dot11BlockAck::header_size() const {
    return Dot11BlockAckRequest::header_size() + sizeof(_bitmap));
}
