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
#include <iostream>
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

using std::pair;
using std::vector;
using std::string;
using std::list;
using std::runtime_error;

namespace Tins {
const Dot11::address_type Dot11::BROADCAST = "ff:ff:ff:ff:ff:ff";

Dot11::Dot11(const address_type &dst_hw_addr, PDU* child) 
: PDU(ETHERTYPE_IP, child), _options_size(0) 
{
    memset(&this->_header, 0, sizeof(ieee80211_header));
    addr1(dst_hw_addr);
}

Dot11::Dot11(const NetworkInterface &iface, 
  const address_type &dst_hw_addr, PDU* child) 
: PDU(ETHERTYPE_IP, child), _options_size(0) 
{
    memset(&_header, 0, sizeof(ieee80211_header));
    addr1(dst_hw_addr);
    this->iface(iface);
}

Dot11::Dot11(const ieee80211_header *header_ptr) 
: PDU(ETHERTYPE_IP) 
{

}

Dot11::Dot11(const uint8_t *buffer, uint32_t total_sz) 
: PDU(ETHERTYPE_IP), _options_size(0) 
{
    /*if(total_sz < sizeof(_header.control))
        throw runtime_error("Not enough size for an IEEE 802.11 header in the buffer.");
    uint32_t sz = std::min((uint32_t)sizeof(_header), total_sz);
    std::memcpy(&_header, buffer, sz);
    buffer += sz;
    total_sz -= sz;*/
    if(total_sz < sizeof(_header))
        throw runtime_error("Not enough size for an IEEE 802.11 header in the buffer.");
    std::memcpy(&_header, buffer, sizeof(_header));
}

Dot11::Dot11(const Dot11 &other) : PDU(other) {
    copy_80211_fields(&other);
}

Dot11::~Dot11() {
    while(_options.size()) {
        delete[] _options.front().value;
        _options.pop_front();
    }
}

Dot11 &Dot11::operator= (const Dot11 &other) {
    copy_80211_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

void Dot11::parse_tagged_parameters(const uint8_t *buffer, uint32_t total_sz) {
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

Dot11::Dot11Option::Dot11Option(uint8_t opt, uint8_t len, const uint8_t *val) : option(opt), length(len) {
    value = new uint8_t[len];
    std::memcpy(value, val, len);
}

void Dot11::add_tagged_option(TaggedOption opt, uint8_t len, const uint8_t *val) {
    uint32_t opt_size = len + (sizeof(uint8_t) << 1);
    _options.push_back(Dot11Option((uint8_t)opt, len, val));
    _options_size += opt_size;
}

const Dot11::Dot11Option *Dot11::search_option(TaggedOption opt) const {
    for(std::list<Dot11Option>::const_iterator it = _options.begin(); it != _options.end(); ++it)
        if(it->option == (uint8_t)opt)
            return &(*it);
    return 0;
}

void Dot11::protocol(uint8_t new_proto) {
    this->_header.control.protocol = new_proto;
}

void Dot11::type(uint8_t new_type) {
    this->_header.control.type = new_type;
}

void Dot11::subtype(uint8_t new_subtype) {
    this->_header.control.subtype = new_subtype;
}

void Dot11::to_ds(bool new_value) {
    this->_header.control.to_ds = (new_value)? 1 : 0;
}

void Dot11::from_ds(bool new_value) {
    this->_header.control.from_ds = (new_value)? 1 : 0;
}

void Dot11::more_frag(bool new_value) {
    this->_header.control.more_frag = (new_value)? 1 : 0;
}

void Dot11::retry(bool new_value) {
    this->_header.control.retry = (new_value)? 1 : 0;
}

void Dot11::power_mgmt(bool new_value) {
    this->_header.control.power_mgmt = (new_value)? 1 : 0;
}

void Dot11::wep(bool new_value) {
    this->_header.control.wep = (new_value)? 1 : 0;
}

void Dot11::order(bool new_value) {
    this->_header.control.order = (new_value)? 1 : 0;
}

void Dot11::duration_id(uint16_t new_duration_id) {
    this->_header.duration_id = new_duration_id;
}

void Dot11::addr1(const address_type &new_addr1) {
    std::copy(new_addr1.begin(), new_addr1.end(), _header.addr1);
}

void Dot11::iface(const NetworkInterface &new_iface) {
    this->_iface = new_iface;
}

uint32_t Dot11::header_size() const {
    uint32_t sz = sizeof(ieee80211_header) + _options_size;
    return sz;
}

bool Dot11::send(PacketSender* sender) {
    struct sockaddr_ll addr;

    memset(&addr, 0, sizeof(struct sockaddr_ll));

    addr.sll_family = Utils::host_to_be<uint16_t>(PF_PACKET);
    addr.sll_protocol = Utils::host_to_be<uint16_t>(ETH_P_ALL);
    addr.sll_halen = 6;
    addr.sll_ifindex = this->_iface.id();
    memcpy(&(addr.sll_addr), this->_header.addr1, 6);

    return sender->send_l2(this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
}

void Dot11::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    uint32_t my_sz = header_size();
    assert(total_sz >= my_sz);
    memcpy(buffer, &_header, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);

    uint32_t written = this->write_ext_header(buffer, total_sz);
    buffer += written;
    total_sz -= written;

    uint32_t child_len = write_fixed_parameters(buffer, total_sz - _options_size);
    buffer += child_len;
    assert(total_sz >= child_len + _options_size);
    for(std::list<Dot11Option>::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        *(buffer++) = it->option;
        *(buffer++) = it->length;
        std::memcpy(buffer, it->value, it->length);
        buffer += it->length;
    }
}

PDU *Dot11::from_bytes(const uint8_t *buffer, uint32_t total_sz) {
    // We only need the control field, the length of the PDU will depend on the flags set.
    if(total_sz < sizeof(ieee80211_header::control))
        throw runtime_error("Not enough size for a IEEE 802.11 header in the buffer.");
    const ieee80211_header *hdr = (const ieee80211_header*)buffer;
    PDU *ret = 0;
    if(hdr->control.type == MANAGEMENT && hdr->control.subtype == 8) {
        if(total_sz < sizeof(_header))
            throw runtime_error("Not enough size for an IEEE 802.11 header in the buffer.");
        ret = new Dot11Beacon(buffer, total_sz);
    }
    else if(hdr->control.type == DATA){
        if(hdr->control.subtype <= 4)
            ret = new Dot11Data(buffer, total_sz);
        else
            ret = new Dot11QoSData(buffer, total_sz);
    }
    else if(hdr->control.type == CONTROL){
        if(hdr->control.subtype == ACK)
            ret = new Dot11Ack(buffer, total_sz);
        else if(hdr->control.subtype == CF_END)
            ret = new Dot11CFEnd(buffer, total_sz);
        else if(hdr->control.subtype == CF_END_ACK)
            ret = new Dot11EndCFAck(buffer, total_sz);
        else if(hdr->control.subtype == PS)
            ret = new Dot11PSPoll(buffer, total_sz);
        else if(hdr->control.subtype == RTS)
            ret = new Dot11RTS(buffer, total_sz);
        else if(hdr->control.subtype == BLOCK_ACK)
            ret = new Dot11BlockAck(buffer, total_sz);
        else if(hdr->control.subtype == BLOCK_ACK_REQ)
            ret = new Dot11BlockAckRequest(buffer, total_sz);
    }
    else
        ret = new Dot11(buffer, total_sz);
    return ret;
}

void Dot11::copy_80211_fields(const Dot11 *other) {
    std::memcpy(&_header, &other->_header, sizeof(_header));
    _iface = other->_iface;
    _options_size = other->_options_size;
    for(std::list<Dot11Option>::const_iterator it = other->_options.begin(); it != other->_options.end(); ++it)
        _options.push_back(Dot11Option(it->option, it->length, it->value));
}

/* Dot11ManagementFrame */

Dot11ManagementFrame::Dot11ManagementFrame(const uint8_t *buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz) 
{
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);
    if(total_sz < sizeof(_ext_header))
        throw runtime_error("Not enough size for an IEEE 802.11 header in the buffer.");
    std::memcpy(&_ext_header, buffer, sizeof(_ext_header));
    total_sz -= sizeof(_ext_header);
    if(from_ds() && to_ds() && total_sz >= _addr4.size())
        //std::memcpy(_addr4, buffer + sizeof(_ext_header), sizeof(_addr4));
        _addr4 = buffer + sizeof(_ext_header);
    else
        throw runtime_error("Not enough size for an IEEE 802.11 header in the buffer.");        
}

Dot11ManagementFrame::Dot11ManagementFrame(
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11(dst_hw_addr) 
{
    type(Dot11::MANAGEMENT);
    addr2(src_hw_addr);
}

Dot11ManagementFrame::Dot11ManagementFrame(const NetworkInterface &iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11(iface, dst_hw_addr) 
{
    type(Dot11::MANAGEMENT);
    addr2(src_hw_addr);
}

Dot11ManagementFrame::Dot11ManagementFrame(const Dot11ManagementFrame &other) : Dot11(other) {
    copy_ext_header(&other);
}

void Dot11ManagementFrame::copy_ext_header(const Dot11ManagementFrame* other) {
    Dot11::copy_80211_fields(other);
    std::memcpy(&_ext_header, &other->_ext_header, sizeof(_ext_header));
    //std::memcpy(_addr4, other->_addr4, 6);
    _addr4 = other->_addr4;
}

uint32_t Dot11ManagementFrame::header_size() const {
    uint32_t sz = Dot11::header_size() + sizeof(_ext_header);
    if (this->from_ds() && this->to_ds())
        sz += 6;
    return sz;
}

void Dot11ManagementFrame::addr2(const address_type &new_addr2) {
    std::copy(new_addr2.begin(), new_addr2.end(), _ext_header.addr2);
}

void Dot11ManagementFrame::addr3(const address_type &new_addr3) {
    std::copy(new_addr3.begin(), new_addr3.end(), _ext_header.addr3);
}

void Dot11ManagementFrame::frag_num(uint8_t new_frag_num) {
    this->_ext_header.seq_control.frag_number = new_frag_num;
}

void Dot11ManagementFrame::seq_num(uint16_t new_seq_num) {
    this->_ext_header.seq_control.seq_number = new_seq_num;
}

void Dot11ManagementFrame::addr4(const address_type &new_addr4) {
    _addr4 = new_addr4;
}

uint32_t Dot11ManagementFrame::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    uint32_t written = sizeof(_ext_header);
    memcpy(buffer, &_ext_header, sizeof(this->_ext_header));
    buffer += sizeof(_ext_header);
    if (from_ds() && to_ds()) {
        written += 6;
        std::copy(_addr4.begin(), _addr4.end(), buffer);
    }
    return written;
}

void Dot11ManagementFrame::ssid(const std::string &new_ssid) {
    add_tagged_option(Dot11::SSID, new_ssid.size(), (const uint8_t*)new_ssid.c_str());
}

void Dot11ManagementFrame::rsn_information(const RSNInformation& info) {
    uint32_t size;
    uint8_t *buffer = info.serialize(size);
    add_tagged_option(RSN, size, buffer);
    delete[] buffer;
}

void Dot11ManagementFrame::supported_rates(const std::list<float> &new_rates) {
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

void Dot11ManagementFrame::extended_supported_rates(const std::list<float> &new_rates) {
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

void Dot11ManagementFrame::qos_capabilities(uint8_t new_qos_capabilities) {
    add_tagged_option(QOS_CAPABILITY, 1, &new_qos_capabilities);
}

void Dot11ManagementFrame::power_capabilities(uint8_t min_power, uint8_t max_power) {
    uint8_t buffer[2];
    buffer[0] = min_power;
    buffer[1] = max_power;
    add_tagged_option(POWER_CAPABILITY, 2, buffer);
}

void Dot11ManagementFrame::supported_channels(const std::list<std::pair<uint8_t, uint8_t> > &new_channels) {
    uint8_t* buffer = new uint8_t[new_channels.size() * 2];
    uint8_t* ptr = buffer;
    for(std::list<pair<uint8_t, uint8_t> >::const_iterator it = new_channels.begin(); it != new_channels.end(); ++it) {
        *(ptr++) = it->first;
        *(ptr++) = it->second;
    }
    add_tagged_option(SUPPORTED_CHANNELS, new_channels.size() * 2, buffer);
    delete[] buffer;
}

void Dot11ManagementFrame::edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo) {
    uint8_t buffer[18];
    buffer[0] = 0;
    uint32_t* ptr = (uint32_t*)(buffer + 1);
    *(ptr++) = ac_be;
    *(ptr++) = ac_bk;
    *(ptr++) = ac_vi;
    *(ptr++) = ac_vo;
    add_tagged_option(EDCA, 18, buffer);
}

void Dot11ManagementFrame::request_information(const std::list<uint8_t> elements) {
    uint16_t sz = elements.size();
    list<uint8_t>::const_iterator it = elements.begin();
    uint8_t* buffer = new uint8_t[sz];
    for (uint16_t i = 0; i < sz; i++) {
        buffer[i] = *it;
        it++;
    }
    add_tagged_option(REQUEST, sz, buffer);
    delete[] buffer;
}

void Dot11ManagementFrame::fh_parameter_set(uint16_t dwell_time, uint8_t hop_set, uint8_t hop_pattern, uint8_t hop_index) {
    uint8_t buffer[5];
    uint16_t* ptr_buffer = (uint16_t*)buffer;
    ptr_buffer[0] = dwell_time;
    buffer[2] = hop_set;
    buffer[3] = hop_pattern;
    buffer[4] = hop_index;
    add_tagged_option(FH_SET, 5, buffer);

}

void Dot11ManagementFrame::ds_parameter_set(uint8_t current_channel) {
    add_tagged_option(DS_SET, 1, &current_channel);
}

void Dot11ManagementFrame::cf_parameter_set(uint8_t cfp_count,
                                                  uint8_t cfp_period,
                                                  uint16_t cfp_max_duration,
                                                  uint16_t cfp_dur_remaining) {
    uint8_t buffer[6];
    uint16_t* ptr_buffer = (uint16_t*)buffer;
    buffer[0] = cfp_count;
    buffer[1] = cfp_period;
    ptr_buffer[1] = cfp_max_duration;
    ptr_buffer[2] = cfp_dur_remaining;
    add_tagged_option(CF_SET, 6, buffer);

}

void Dot11ManagementFrame::ibss_parameter_set(uint16_t atim_window) {
    add_tagged_option(IBSS_SET, 2, (uint8_t*)&atim_window);
}

void Dot11ManagementFrame::country(const std::vector<uint8_t*>& countries,
                                         const std::vector<uint8_t>& first_channels,
                                         const std::vector<uint8_t>& number_channels,
                                         const std::vector<uint8_t>& max_power) {

    /* Check that the lists have the same number of elements */
    if ((countries.size() != first_channels.size()) ||
        (countries.size() != number_channels.size()) ||
        (countries.size() != max_power.size()))
        throw runtime_error("Lists should be of equal length!");

    uint8_t sz = 6 * countries.size();
    if (sz & 1) // If size is odd, pad it
        sz++;
    uint8_t* buffer = new uint8_t[sz];
    uint8_t* ptr_buffer = buffer;
    for (uint8_t i = 0; i < countries.size(); i++) {
        memcpy(ptr_buffer, countries[i], 3);
        ptr_buffer += 3;
        *ptr_buffer = first_channels[i];
        ptr_buffer++;
        *ptr_buffer = number_channels[i];
        ptr_buffer++;
        *ptr_buffer = max_power[i];
        ptr_buffer++;
    }
    add_tagged_option(COUNTRY, sz, buffer);
    delete[] buffer;

}

void Dot11ManagementFrame::fh_parameters(uint8_t prime_radix, uint8_t number_channels) {
    uint8_t buffer[2];
    buffer[0] = prime_radix;
    buffer[1] = number_channels;
    add_tagged_option(HOPPING_PATTERN_PARAMS, 2, buffer);
}

void Dot11ManagementFrame::fh_pattern_table(uint8_t flag,
                                                  uint8_t number_of_sets,
                                                  uint8_t modulus,
                                                  uint8_t offset,
                                                  const vector<uint8_t>& random_table) {

    uint8_t sz = 4 + random_table.size();
    uint8_t* buffer = new uint8_t[sz];
    buffer[0] = flag;
    buffer[1] = number_of_sets;
    buffer[2] = modulus;
    buffer[3] = offset;
    uint8_t* ptr_buffer = &buffer[4];
    for (vector<uint8_t>::const_iterator it = random_table.begin(); it != random_table.end(); it++)
        *(ptr_buffer++) = *it;
    add_tagged_option(HOPPING_PATTERN_TABLE, sz, buffer);
    delete[] buffer;
}

void Dot11ManagementFrame::power_constraint(uint8_t local_power_constraint) {
    add_tagged_option(POWER_CONSTRAINT, 1, &local_power_constraint);
}

void Dot11ManagementFrame::channel_switch(uint8_t switch_mode, uint8_t new_channel, uint8_t switch_count) {

    uint8_t buffer[3];
    buffer[0] = switch_mode;
    buffer[1] = new_channel;
    buffer[2] = switch_count;
    add_tagged_option(CHANNEL_SWITCH, 3, buffer);

}

void Dot11ManagementFrame::quiet(uint8_t quiet_count, uint8_t quiet_period, uint16_t quiet_duration, uint16_t quiet_offset) {

    uint8_t buffer[6];
    uint16_t* ptr_buffer = (uint16_t*)buffer;

    buffer[0] = quiet_count;
    buffer[1] = quiet_period;
    ptr_buffer[1] = quiet_duration;
    ptr_buffer[2] = quiet_offset;
    add_tagged_option(QUIET, 6, buffer);

}

void Dot11ManagementFrame::ibss_dfs(const uint8_t* dfs_owner, uint8_t recovery_interval, const vector<pair<uint8_t, uint8_t> >& channel_map) {

    uint8_t sz = 7 + 2 * channel_map.size();
    uint8_t* buffer = new uint8_t[sz];
    uint8_t* ptr_buffer = buffer;

    memcpy(ptr_buffer, dfs_owner, 6);
    ptr_buffer += 6;
    *(ptr_buffer++) = recovery_interval;
    for (vector<pair<uint8_t, uint8_t> >::const_iterator it = channel_map.begin(); it != channel_map.end(); it++) {
        *(ptr_buffer++) = it->first;
        *(ptr_buffer++) = it->second;
    }

    add_tagged_option(IBSS_DFS, sz, buffer);

    delete[] buffer;

}

void Dot11ManagementFrame::tpc_report(uint8_t transmit_power, uint8_t link_margin) {

    uint8_t buffer[2];
    buffer[0] = transmit_power;
    buffer[1] = link_margin;
    add_tagged_option(TPC_REPORT, 2, buffer);

}

void Dot11ManagementFrame::erp_information(uint8_t value) {
    add_tagged_option(ERP_INFORMATION, 1, &value);
}

void Dot11ManagementFrame::bss_load(uint16_t station_count, uint8_t channel_utilization, uint16_t available_capacity) {
    uint8_t buffer[5];

    buffer[0] = station_count & 0xFF;
    buffer[1] = station_count >> 8;
    buffer[2] = channel_utilization;
    buffer[3] = available_capacity & 0xFF;
    buffer[4] = available_capacity >> 8;
    add_tagged_option(BSS_LOAD, 5, buffer);
}

void Dot11ManagementFrame::tim(uint8_t dtim_count,
                                     uint8_t dtim_period,
                                     uint8_t bitmap_control,
                                     uint8_t* partial_virtual_bitmap,
                                     uint8_t partial_virtual_bitmap_sz) {

    uint8_t sz = 3 + partial_virtual_bitmap_sz;
    uint8_t* buffer = new uint8_t[sz];
    buffer[0] = dtim_count;
    buffer[1] = dtim_period;
    buffer[2] = bitmap_control;
    memcpy(buffer + 3, partial_virtual_bitmap, partial_virtual_bitmap_sz);
    add_tagged_option(TIM, sz, buffer);
}

void Dot11ManagementFrame::challenge_text(uint8_t* ch_text, uint8_t ch_text_sz) {
    add_tagged_option(CHALLENGE_TEXT, ch_text_sz, ch_text);
}

/* Dot11Beacon */

Dot11Beacon::Dot11Beacon(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) {
    subtype(Dot11::BEACON);
    memset(&_body, 0, sizeof(_body));
}

Dot11Beacon::Dot11Beacon(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr)
{
    subtype(Dot11::BEACON);
    memset(&_body, 0, sizeof(_body));
}

Dot11Beacon::Dot11Beacon(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) 
{
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw runtime_error("Not enough size for a IEEE 802.11 beacon header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11Beacon::timestamp(uint64_t new_timestamp) {
    this->_body.timestamp = new_timestamp;
}

void Dot11Beacon::interval(uint16_t new_interval) {
    this->_body.interval = new_interval;
}

void Dot11Beacon::essid(const std::string &new_essid) {
    Dot11ManagementFrame::ssid(new_essid);
}

void Dot11Beacon::supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::supported_rates(new_rates);
}

void Dot11Beacon::ds_parameter_set(uint8_t current_channel) {
    Dot11ManagementFrame::ds_parameter_set(current_channel);
}

void Dot11Beacon::fh_parameter_set(uint16_t dwell_time,
                                         uint8_t hop_set,
                                         uint8_t hop_pattern,
                                         uint8_t hop_index) {
    Dot11ManagementFrame::fh_parameter_set(dwell_time, hop_set, hop_pattern, hop_index);
}

void Dot11Beacon::cf_parameter_set(uint8_t cfp_count,
                                         uint8_t cfp_period,
                                         uint16_t cfp_max_duration,
                                         uint16_t cfp_dur_remaining) {
    Dot11ManagementFrame::cf_parameter_set(cfp_count, cfp_period, cfp_max_duration, cfp_dur_remaining);
}

void Dot11Beacon::ibss_parameter_set(uint16_t atim_window) {
    Dot11ManagementFrame::ibss_parameter_set(atim_window);
}

void Dot11Beacon::tim(uint8_t dtim_count,
                            uint8_t dtim_period,
                            uint8_t bitmap_control,
                            uint8_t* partial_virtual_bitmap,
                            uint8_t partial_virtual_bitmap_sz) {
    Dot11ManagementFrame::tim(dtim_count, dtim_period, bitmap_control, partial_virtual_bitmap, partial_virtual_bitmap_sz);
}

void Dot11Beacon::country(const std::vector<uint8_t*>& countries,
                                const std::vector<uint8_t>& first_channels,
                                const std::vector<uint8_t>& number_channels,
                                const std::vector<uint8_t>& max_power) {
    Dot11ManagementFrame::country(countries, first_channels, number_channels, max_power);
}

void Dot11Beacon::fh_parameters(uint8_t prime_radix, uint8_t number_channels) {
    Dot11ManagementFrame::fh_parameters(prime_radix, number_channels);
}

void Dot11Beacon::fh_pattern_table(uint8_t flag,
                                         uint8_t number_of_sets,
                                         uint8_t modulus,
                                         uint8_t offset,
                                         const std::vector<uint8_t>& random_table) {
    Dot11ManagementFrame::fh_pattern_table(flag, number_of_sets, modulus, offset, random_table);
}

void Dot11Beacon::power_constraint(uint8_t local_power_constraint) {
    Dot11ManagementFrame::power_constraint(local_power_constraint);
}

void Dot11Beacon::channel_switch(uint8_t switch_mode, uint8_t new_channel, uint8_t switch_count) {
    Dot11ManagementFrame::channel_switch(switch_mode, new_channel, switch_count);
}

void Dot11Beacon::quiet(uint8_t quiet_count, uint8_t quiet_period, uint16_t quiet_duration, uint16_t quiet_offset) {
    Dot11ManagementFrame::quiet(quiet_count, quiet_period, quiet_duration, quiet_offset);
}

void Dot11Beacon::ibss_dfs(const uint8_t* dfs_owner,
                                 uint8_t recovery_interval,
                                 const std::vector<std::pair<uint8_t, uint8_t> >& channel_map) {
    Dot11ManagementFrame::ibss_dfs(dfs_owner, recovery_interval, channel_map);
}

void Dot11Beacon::tpc_report(uint8_t transmit_power, uint8_t link_margin) {
    Dot11ManagementFrame::tpc_report(transmit_power, link_margin);
}

void Dot11Beacon::erp_information(uint8_t value) {
    Dot11ManagementFrame::erp_information(value);
}

void Dot11Beacon::extended_supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::extended_supported_rates(new_rates);
}

void Dot11Beacon::rsn_information(const RSNInformation& info) {
    Dot11ManagementFrame::rsn_information(info);
}

void Dot11Beacon::bss_load(uint16_t station_count,
                                 uint8_t channel_utilization,
                                 uint16_t available_capacity) {
    Dot11ManagementFrame::bss_load(station_count, channel_utilization, available_capacity);
}

void Dot11Beacon::edca_parameter_set(uint32_t ac_be,
                                           uint32_t ac_bk,
                                           uint32_t ac_vi,
                                           uint32_t ac_vo) {
    Dot11ManagementFrame::edca_parameter_set(ac_be, ac_bk, ac_vi, ac_vo);
}

void Dot11Beacon::qos_capabilities(uint8_t qos_info) {
    Dot11ManagementFrame::qos_capabilities(qos_info);
}

string Dot11Beacon::essid() const {
    const Dot11::Dot11Option *option = search_option(SSID);
    return (option) ? string((const char*)option->value, option->length) : 0;
}

bool Dot11Beacon::rsn_information(RSNInformation *rsn) {
    const Dot11::Dot11Option *option = search_option(RSN);
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

uint32_t Dot11Beacon::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(_body);
}

uint32_t Dot11Beacon::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(_body);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

PDU *Dot11Beacon::clone_pdu() const {
    Dot11Beacon *new_pdu = new Dot11Beacon();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    std::memcpy(&new_pdu->_body, &_body, sizeof(_body));
    return new_pdu;
}

/* Diassoc */

Dot11Disassoc::Dot11Disassoc(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) {
    subtype(Dot11::DISASSOC);
    memset(&_body, 0, sizeof(_body));
}

Dot11Disassoc::Dot11Disassoc(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr){
    this->subtype(Dot11::DISASSOC);
    memset(&_body, 0, sizeof(_body));
}

Dot11Disassoc::Dot11Disassoc(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw runtime_error("Not enough size for a IEEE 802.11 disassociation header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11Disassoc::reason_code(uint16_t new_reason_code) {
    this->_body.reason_code = new_reason_code;
}

uint32_t Dot11Disassoc::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(DisassocBody);
}

uint32_t Dot11Disassoc::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(DisassocBody);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

PDU *Dot11Disassoc::clone_pdu() const {
    Dot11Disassoc *new_pdu = new Dot11Disassoc();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    memcpy(&new_pdu->_body, &this->_body, sizeof(this->_body));
    return new_pdu;
}

/* Assoc request. */

Dot11AssocRequest::Dot11AssocRequest(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    subtype(Dot11::ASSOC_REQ);
    memset(&_body, 0, sizeof(_body));
}

Dot11AssocRequest::Dot11AssocRequest(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr)
{
    subtype(Dot11::ASSOC_REQ);
    memset(&_body, 0, sizeof(_body));
}

Dot11AssocRequest::Dot11AssocRequest(const uint8_t *buffer, uint32_t total_sz) : Dot11ManagementFrame(buffer, total_sz) {
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw runtime_error("Not enough size for an IEEE 802.11 association request header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11AssocRequest::listen_interval(uint16_t new_listen_interval) {
    this->_body.listen_interval = new_listen_interval;
}

void Dot11AssocRequest::ssid(const std::string &new_ssid) {
    Dot11ManagementFrame::ssid(new_ssid);
}

void Dot11AssocRequest::supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::supported_rates(new_rates);
}

void Dot11AssocRequest::extended_supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::extended_supported_rates(new_rates);
}

void Dot11AssocRequest::power_capabilities(uint8_t min_power, uint8_t max_power) {
    Dot11ManagementFrame::power_capabilities(min_power, max_power);
}

void Dot11AssocRequest::supported_channels(const std::list<pair<uint8_t, uint8_t> > &new_channels) {
    Dot11ManagementFrame::supported_channels(new_channels);
}

void Dot11AssocRequest::rsn_information(const RSNInformation& info) {
    Dot11ManagementFrame::rsn_information(info);
}

void Dot11AssocRequest::qos_capabilities(uint8_t new_qos_capabilities) {
    Dot11ManagementFrame::qos_capabilities(new_qos_capabilities);
}

uint32_t Dot11AssocRequest::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(AssocReqBody);
}

uint32_t Dot11AssocRequest::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(AssocReqBody);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

PDU *Dot11AssocRequest::clone_pdu() const {
    Dot11AssocRequest *new_pdu = new Dot11AssocRequest();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    std::memcpy(&new_pdu->_body, &_body, sizeof(_body));
    return new_pdu;
}

/* Assoc response. */

Dot11AssocResponse::Dot11AssocResponse(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    subtype(Dot11::ASSOC_RESP);
    memset(&_body, 0, sizeof(_body));
}

Dot11AssocResponse::Dot11AssocResponse(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr) 
{
    subtype(Dot11::ASSOC_RESP);
    memset(&_body, 0, sizeof(_body));
}

Dot11AssocResponse::Dot11AssocResponse(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) 
{
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw runtime_error("Not enough size for an IEEE 802.11 association response header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11AssocResponse::status_code(uint16_t new_status_code) {
    this->_body.status_code = new_status_code;
}

void Dot11AssocResponse::aid(uint16_t new_aid) {
    this->_body.aid = new_aid;
}

void Dot11AssocResponse::supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::supported_rates(new_rates);
}

void Dot11AssocResponse::extended_supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::extended_supported_rates(new_rates);
}

void Dot11AssocResponse::edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo) {
    Dot11ManagementFrame::edca_parameter_set(ac_be, ac_bk, ac_vi, ac_vo);
}

uint32_t Dot11AssocResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(AssocRespBody);
}

uint32_t Dot11AssocResponse::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(AssocRespBody);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

PDU *Dot11AssocResponse::clone_pdu() const {
    Dot11AssocResponse *new_pdu = new Dot11AssocResponse();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    std::memcpy(&new_pdu->_body, &_body, sizeof(_body));
    return new_pdu;
}

/* ReAssoc request. */

Dot11ReAssocRequest::Dot11ReAssocRequest(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::REASSOC_REQ);
    memset(&_body, 0, sizeof(_body));
}

Dot11ReAssocRequest::Dot11ReAssocRequest(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr)
{
    this->subtype(Dot11::REASSOC_REQ);
    memset(&_body, 0, sizeof(_body));
}

Dot11ReAssocRequest::Dot11ReAssocRequest(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) 
{
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw runtime_error("Not enough size for an IEEE 802.11 reassociation request header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11ReAssocRequest::listen_interval(uint16_t new_listen_interval) {
    this->_body.listen_interval = new_listen_interval;
}

void Dot11ReAssocRequest::current_ap(uint8_t* new_current_ap) {
    memcpy(this->_body.current_ap, new_current_ap, 6);
}

void Dot11ReAssocRequest::ssid(const std::string &new_ssid) {
    Dot11ManagementFrame::ssid(new_ssid);
}

void Dot11ReAssocRequest::supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::supported_rates(new_rates);
}

void Dot11ReAssocRequest::extended_supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::extended_supported_rates(new_rates);
}

void Dot11ReAssocRequest::power_capabilities(uint8_t min_power, uint8_t max_power) {
    Dot11ManagementFrame::power_capabilities(min_power, max_power);
}

void Dot11ReAssocRequest::supported_channels(const std::list<pair<uint8_t, uint8_t> > &new_channels) {
    Dot11ManagementFrame::supported_channels(new_channels);
}

void Dot11ReAssocRequest::rsn_information(const RSNInformation& info) {
    Dot11ManagementFrame::rsn_information(info);
}

void Dot11ReAssocRequest::qos_capabilities(uint8_t new_qos_capabilities) {
    Dot11ManagementFrame::qos_capabilities(new_qos_capabilities);
}

uint32_t Dot11ReAssocRequest::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(this->_body);
}

uint32_t Dot11ReAssocRequest::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

PDU *Dot11ReAssocRequest::clone_pdu() const {
    Dot11ReAssocRequest *new_pdu = new Dot11ReAssocRequest();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    std::memcpy(&new_pdu->_body, &_body, sizeof(_body));
    return new_pdu;
}

/* ReAssoc response. */

Dot11ReAssocResponse::Dot11ReAssocResponse(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::REASSOC_RESP);
    memset(&_body, 0, sizeof(_body));
}

Dot11ReAssocResponse::Dot11ReAssocResponse(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr)
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::REASSOC_RESP);
    memset(&_body, 0, sizeof(_body));
}

Dot11ReAssocResponse::Dot11ReAssocResponse(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw runtime_error("Not enough size for an IEEE 802.11 reassociation response header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11ReAssocResponse::status_code(uint16_t new_status_code) {
    this->_body.status_code = new_status_code;
}

void Dot11ReAssocResponse::aid(uint16_t new_aid) {
    this->_body.aid = new_aid;
}

void Dot11ReAssocResponse::supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::supported_rates(new_rates);
}

void Dot11ReAssocResponse::extended_supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::extended_supported_rates(new_rates);
}

void Dot11ReAssocResponse::edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo) {
    Dot11ManagementFrame::edca_parameter_set(ac_be, ac_bk, ac_vi, ac_vo);
}

uint32_t Dot11ReAssocResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(this->_body);
}

uint32_t Dot11ReAssocResponse::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

PDU *Dot11ReAssocResponse::clone_pdu() const {
    Dot11ReAssocResponse *new_pdu = new Dot11ReAssocResponse();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    std::memcpy(&new_pdu->_body, &_body, sizeof(_body));
    return new_pdu;
}

/* Probe Request */

Dot11ProbeRequest::Dot11ProbeRequest(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::PROBE_REQ);
}

Dot11ProbeRequest::Dot11ProbeRequest(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::PROBE_REQ);
}

Dot11ProbeRequest::Dot11ProbeRequest(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) 
{
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11ProbeRequest::ssid(const std::string &new_ssid) {
    Dot11ManagementFrame::ssid(new_ssid);
}

void Dot11ProbeRequest::supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::supported_rates(new_rates);
}

void Dot11ProbeRequest::request_information(const std::list<uint8_t> elements) {
    Dot11ManagementFrame::request_information(elements);
}

void Dot11ProbeRequest::extended_supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::extended_supported_rates(new_rates);
}

PDU* Dot11ProbeRequest::clone_pdu() const {
    Dot11ProbeRequest* new_pdu = new Dot11ProbeRequest();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    return new_pdu;
}

/* Probe Response */

Dot11ProbeResponse::Dot11ProbeResponse(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::PROBE_RESP);
    memset(&this->_body, 0, sizeof(this->_body));
}

Dot11ProbeResponse::Dot11ProbeResponse(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::PROBE_RESP);
    memset(&this->_body, 0, sizeof(this->_body));
}

Dot11ProbeResponse::Dot11ProbeResponse(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) 
{
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw runtime_error("Not enough size for an IEEE 802.11 probe response header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11ProbeResponse::timestamp(uint64_t new_timestamp) {
    this->_body.timestamp = new_timestamp;
}

void Dot11ProbeResponse::interval(uint16_t new_interval) {
    this->_body.interval = new_interval;
}

void Dot11ProbeResponse::ssid(const std::string &new_ssid) {
    Dot11ManagementFrame::ssid(new_ssid);
}

void Dot11ProbeResponse::supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::supported_rates(new_rates);
}

void Dot11ProbeResponse::fh_parameter_set(uint16_t dwell_time, uint8_t hop_set, uint8_t hop_pattern, uint8_t hop_index) {
    Dot11ManagementFrame::fh_parameter_set(dwell_time, hop_set, hop_pattern, hop_index);
}

void Dot11ProbeResponse::ds_parameter_set(uint8_t current_channel) {
    Dot11ManagementFrame::ds_parameter_set(current_channel);
}

void Dot11ProbeResponse::cf_parameter_set(uint8_t cfp_count, uint8_t cfp_period, uint16_t cfp_max_duration, uint16_t cfp_dur_remaining) {
    Dot11ManagementFrame::cf_parameter_set(cfp_count, cfp_period, cfp_max_duration, cfp_dur_remaining);
}

void Dot11ProbeResponse::ibss_parameter_set(uint16_t atim_window) {
    Dot11ManagementFrame::ibss_parameter_set(atim_window);
}

void Dot11ProbeResponse::country(const std::vector<uint8_t*>& countries,
                                       const std::vector<uint8_t>& first_channels,
                                       const std::vector<uint8_t>& number_channels,
                                       const std::vector<uint8_t>& max_power) {
    Dot11ManagementFrame::country(countries, first_channels, number_channels, max_power);
}

void Dot11ProbeResponse::fh_parameters(uint8_t prime_radix, uint8_t number_channels) {
    Dot11ManagementFrame::fh_parameters(prime_radix, number_channels);
}

void Dot11ProbeResponse::fh_pattern_table(uint8_t flag,
                                                uint8_t number_of_sets,
                                                uint8_t modulus,
                                                uint8_t offset,
                                                const std::vector<uint8_t>& random_table) {
    Dot11ManagementFrame::fh_pattern_table(flag, number_of_sets, modulus, offset, random_table);
}

void Dot11ProbeResponse::power_constraint(uint8_t local_power_constraint) {
    Dot11ManagementFrame::power_constraint(local_power_constraint);
}

void Dot11ProbeResponse::channel_switch(uint8_t switch_mode, uint8_t new_channel, uint8_t switch_count) {
    Dot11ManagementFrame::channel_switch(switch_mode, new_channel, switch_count);
}

void Dot11ProbeResponse::quiet(uint8_t quiet_count, uint8_t quiet_period, uint16_t quiet_duration, uint16_t quiet_offset) {
    Dot11ManagementFrame::quiet(quiet_count, quiet_period, quiet_duration, quiet_offset);
}

void Dot11ProbeResponse::ibss_dfs(const uint8_t* dfs_owner,
                                        uint8_t recovery_interval,
                                        const std::vector<std::pair<uint8_t, uint8_t> >& channel_map) {
    Dot11ManagementFrame::ibss_dfs(dfs_owner, recovery_interval, channel_map);
}

void Dot11ProbeResponse::tpc_report(uint8_t transmit_power, uint8_t link_margin) {
    Dot11ManagementFrame::tpc_report(transmit_power, link_margin);
}

void Dot11ProbeResponse::erp_information(uint8_t value) {
    Dot11ManagementFrame::erp_information(value);
}

void Dot11ProbeResponse::extended_supported_rates(const std::list<float> &new_rates) {
    Dot11ManagementFrame::extended_supported_rates(new_rates);
}

void Dot11ProbeResponse::rsn_information(const RSNInformation& info) {
    Dot11ManagementFrame::rsn_information(info);
}

void Dot11ProbeResponse::bss_load(uint16_t station_count,
                                        uint8_t channel_utilization,
                                        uint16_t available_capacity) {
    Dot11ManagementFrame::bss_load(station_count, channel_utilization, available_capacity);
}

void Dot11ProbeResponse::edca_parameter_set(uint32_t ac_be,
                                                  uint32_t ac_bk,
                                                  uint32_t ac_vi,
                                                  uint32_t ac_vo) {
    Dot11ManagementFrame::edca_parameter_set(ac_be, ac_bk, ac_vi, ac_vo);
}

uint32_t Dot11ProbeResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(this->_body);
}

PDU* Dot11ProbeResponse::clone_pdu() const {
    Dot11ProbeResponse* new_pdu = new Dot11ProbeResponse();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    memcpy(&new_pdu->_body, &this->_body, sizeof(this->_body));
    return new_pdu;
}

uint32_t Dot11ProbeResponse::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* Auth */

Dot11Authentication::Dot11Authentication(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::AUTH);
    memset(&_body, 0, sizeof(_body));
}

Dot11Authentication::Dot11Authentication(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::AUTH);
    memset(&_body, 0, sizeof(_body));
}

Dot11Authentication::Dot11Authentication(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) 
{
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw runtime_error("Not enough size for an IEEE 802.11 authentication header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11Authentication::auth_algorithm(uint16_t new_auth_algorithm) {
    this->_body.auth_algorithm = new_auth_algorithm;
}

void Dot11Authentication::auth_seq_number(uint16_t new_auth_seq_number) {
    this->_body.auth_seq_number = new_auth_seq_number;
}

void Dot11Authentication::status_code(uint16_t new_status_code) {
    this->_body.status_code = new_status_code;
}

void Dot11Authentication::challenge_text(uint8_t* ch_text, uint8_t ch_text_sz) {
    Dot11ManagementFrame::challenge_text(ch_text, ch_text_sz);
}

uint32_t Dot11Authentication::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(this->_body);
}

PDU* Dot11Authentication::clone_pdu() const {
    Dot11Authentication *new_pdu = new Dot11Authentication();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    std::memcpy(&new_pdu->_body, &_body, sizeof(_body));
    return new_pdu;
}

uint32_t Dot11Authentication::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* Deauth */

Dot11Deauthentication::Dot11Deauthentication(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr) 
: Dot11ManagementFrame(dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::DEAUTH);
    memset(&_body, 0, sizeof(_body));
}

Dot11Deauthentication::Dot11Deauthentication(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr)
{
    this->subtype(Dot11::DEAUTH);
    memset(&_body, 0, sizeof(_body));
}

Dot11Deauthentication::Dot11Deauthentication(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) {
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_body))
        throw runtime_error("Not enough size for a IEEE 802.11 deauthentication header in the buffer.");
    memcpy(&_body, buffer, sizeof(_body));
    buffer += sizeof(_body);
    total_sz -= sizeof(_body);
    parse_tagged_parameters(buffer, total_sz);
}

void Dot11Deauthentication::reason_code(uint16_t new_reason_code) {
    this->_body.reason_code = new_reason_code;
}

uint32_t Dot11Deauthentication::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(this->_body);
}

uint32_t Dot11Deauthentication::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

PDU *Dot11Deauthentication::clone_pdu() const {
    Dot11Deauthentication *new_pdu = new Dot11Deauthentication();
    new_pdu->copy_80211_fields(this);
    new_pdu->copy_ext_header(this);
    memcpy(&new_pdu->_body, &this->_body, sizeof(this->_body));
    return new_pdu;
}

/* Dot11Data */

Dot11Data::Dot11Data(const uint8_t *buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz) {
    uint32_t sz = Dot11::header_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(_ext_header))
        throw runtime_error("Not enough size for an IEEE 802.11 data header in the buffer.");
    std::memcpy(&_ext_header, buffer, sizeof(_ext_header));
    buffer += sizeof(_ext_header);
    total_sz -= sizeof(_ext_header);
    if(from_ds() && to_ds()) {
        if(total_sz < sizeof(_addr4))
            throw runtime_error("Not enough size for an IEEE 802.11 data header in the buffer.");
        std::memcpy(&_addr4, buffer, sizeof(_addr4));
        buffer += sizeof(_addr4);
        total_sz -= sizeof(_addr4);
    }
    if(total_sz)
        inner_pdu(new Tins::SNAP(buffer, total_sz));
}

Dot11Data::Dot11Data(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr, PDU* child) 
: Dot11(dst_hw_addr, child) 
{
    type(Dot11::DATA);
    addr2(src_hw_addr);
}


Dot11Data::Dot11Data(const NetworkInterface &iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr,
  PDU* child) 
: Dot11(iface, dst_hw_addr, child) 
{
    type(Dot11::DATA);
    addr2(src_hw_addr);
}

void Dot11Data::copy_ext_header(const Dot11Data* other) {
    Dot11::copy_80211_fields(other);
    std::memcpy(&this->_ext_header, &other->_ext_header, sizeof(this->_ext_header));
    std::memcpy(this->_addr4, other->_addr4, 6);
}

uint32_t Dot11Data::header_size() const {
    uint32_t sz = Dot11::header_size() + sizeof(_ext_header);
    if (this->from_ds() && this->to_ds())
        sz += 6;
    return sz;
}

void Dot11Data::addr2(const address_type &new_addr2) {
    std::copy(new_addr2.begin(), new_addr2.end(), _ext_header.addr2);
}

void Dot11Data::addr3(const address_type &new_addr3) {
    std::copy(new_addr3.begin(), new_addr3.end(), _ext_header.addr3);
}

void Dot11Data::frag_num(uint8_t new_frag_num) {
    this->_ext_header.seq_control.frag_number = new_frag_num;
}

void Dot11Data::seq_num(uint16_t new_seq_num) {
    this->_ext_header.seq_control.seq_number = new_seq_num;
}

void Dot11Data::addr4(const uint8_t* new_addr4) {
    memcpy(this->_addr4, new_addr4, 6);
}

uint32_t Dot11Data::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    uint32_t written = sizeof(this->_ext_header);
    memcpy(buffer, &this->_ext_header, sizeof(this->_ext_header));
    buffer += sizeof(this->_ext_header);
    if (this->from_ds() && this->to_ds()) {
        written += 6;
        memcpy(buffer, this->_addr4, 6);
    }
    return written;

}

PDU *Dot11Data::clone_pdu() const {
    Dot11Data *new_pdu = new Dot11Data();
    new_pdu->copy_80211_fields(this);
    return new_pdu;
}

/* QoS data. */

Dot11QoSData::Dot11QoSData(const address_type &dst_hw_addr, 
  const address_type &src_hw_addr, PDU* child) 
: Dot11Data(dst_hw_addr, src_hw_addr, child) 
{

}

Dot11QoSData::Dot11QoSData(const NetworkInterface &iface, 
  const address_type &dst_hw_addr, const address_type &src_hw_addr, 
  PDU* child) 
: Dot11Data(iface, dst_hw_addr, src_hw_addr, child) 
{
    this->subtype(Dot11::QOS_DATA_DATA);
    this->_qos_control = 0;
}

Dot11QoSData::Dot11QoSData(const uint8_t *buffer, uint32_t total_sz) 
// Am I breaking something? :S
//: Dot11Data(buffer, std::min(data_frame_size(), total_sz)) {
: Dot11Data(buffer, total_sz) {
    uint32_t sz = data_frame_size();
    buffer += sz;
    total_sz -= sz;
    if(total_sz < sizeof(this->_qos_control))
        throw runtime_error("Not enough size for an IEEE 802.11 data header in the buffer.");
    this->_qos_control = *(uint16_t*)buffer;
    total_sz -= sizeof(uint16_t);
    buffer += sizeof(uint16_t);
    if(total_sz)
        inner_pdu(new Tins::SNAP(buffer, total_sz));
}

Dot11QoSData::Dot11QoSData(const Dot11QoSData &other) : Dot11Data(other) {
    copy_fields(&other);
}

Dot11QoSData &Dot11QoSData::operator= (const Dot11QoSData &other) {
    copy_inner_pdu(other);
    copy_fields(&other);
    return *this;
}

void Dot11QoSData::copy_fields(const Dot11QoSData *other) {
    Dot11Data::copy_ext_header(other);
    _qos_control = other->_qos_control;
}

void Dot11QoSData::qos_control(uint16_t new_qos_control) {
    this->_qos_control = new_qos_control;
}

uint32_t Dot11QoSData::header_size() const {
    return Dot11::header_size() + sizeof(this->_qos_control);
}

uint32_t Dot11QoSData::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_qos_control);
    assert(sz <= total_sz);
    *(uint16_t*)buffer = this->_qos_control;
    return sz;
}

PDU *Dot11QoSData::clone_pdu() const {
    Dot11QoSData *new_pdu = new Dot11QoSData();
    new_pdu->copy_80211_fields(this);
    return new_pdu;
}

/* Dot11Control */

Dot11Control::Dot11Control(const address_type &dst_addr, PDU* child) 
: Dot11(dst_addr, child) 
{
    type(CONTROL);
}

Dot11Control::Dot11Control(const NetworkInterface &iface, 
  const address_type &dst_addr, PDU* child) 
: Dot11(iface, dst_addr, child) 
{
    type(CONTROL);
}

Dot11Control::Dot11Control(const uint8_t *buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz) {

}

/* Dot11ControlTA */
Dot11ControlTA::Dot11ControlTA(const address_type &dst_addr, 
  const address_type &target_address, PDU* child) 
: Dot11Control(dst_addr, child) 
{
    target_addr(target_address);
}

Dot11ControlTA::Dot11ControlTA(const NetworkInterface &iface, 
  const address_type &dst_addr, const address_type &target_address, PDU* child) 
: Dot11Control(iface, dst_addr, child)
{
    target_addr(target_address);
}

Dot11ControlTA::Dot11ControlTA(const uint8_t *buffer, uint32_t total_sz) : Dot11Control(buffer, total_sz) {
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);
    if(total_sz < sizeof(_taddr))
        throw runtime_error("Not enough size for an IEEE 802.11 RTS frame in the buffer.");
    std::memcpy(_taddr, buffer, sizeof(_taddr));
}

uint32_t Dot11ControlTA::header_size() const {
    return Dot11::header_size() + sizeof(_taddr);
}

uint32_t Dot11ControlTA::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    assert(total_sz >= sizeof(_taddr));
    std::memcpy(buffer, _taddr, sizeof(_taddr));
    return sizeof(_taddr);
}

void Dot11ControlTA::target_addr(const address_type &addr) {
    std::copy(addr.begin(), addr.end(), _taddr);
}

/* Dot11RTS */
Dot11RTS::Dot11RTS(const address_type &dst_addr , 
  const address_type &target_addr, PDU* child) 
:  Dot11ControlTA(dst_addr, target_addr, child) 
{
    subtype(RTS);
}

Dot11RTS::Dot11RTS(const NetworkInterface &iface, const address_type &dst_addr, 
  const address_type &target_addr, PDU* child) 
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    subtype(RTS);
}

Dot11RTS::Dot11RTS(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

PDU *Dot11RTS::clone_pdu() const {
    Dot11RTS *new_pdu = new Dot11RTS();
    new_pdu->copy_80211_fields(this);
    return new_pdu;
}

/* Dot11PSPoll */

Dot11PSPoll::Dot11PSPoll(const address_type &dst_addr, 
  const address_type &target_addr, PDU* child) 
: Dot11ControlTA(dst_addr, target_addr, child) 
{
    subtype(PS);
}

Dot11PSPoll::Dot11PSPoll(const NetworkInterface &iface, 
  const address_type &dst_addr, const address_type &target_addr, PDU* child) 
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    subtype(PS);
}

Dot11PSPoll::Dot11PSPoll(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

PDU *Dot11PSPoll::clone_pdu() const {
    Dot11PSPoll *new_pdu = new Dot11PSPoll();
    new_pdu->copy_80211_fields(this);
    return new_pdu;
}

/* Dot11CFEnd */

Dot11CFEnd::Dot11CFEnd(const address_type &dst_addr, 
  const address_type &target_addr, PDU* child) 
:  Dot11ControlTA(dst_addr, target_addr, child) 
{
    subtype(CF_END);
}

Dot11CFEnd::Dot11CFEnd(const NetworkInterface &iface, 
  const address_type &dst_addr, const address_type &target_addr, PDU* child) 
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    subtype(CF_END);
}

Dot11CFEnd::Dot11CFEnd(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

PDU *Dot11CFEnd::clone_pdu() const {
    Dot11CFEnd *new_pdu = new Dot11CFEnd();
    new_pdu->copy_80211_fields(this);
    return new_pdu;
}

/* Dot11EndCFAck */

Dot11EndCFAck::Dot11EndCFAck(const address_type &dst_addr, 
  const address_type &target_addr, PDU* child) 
:  Dot11ControlTA(dst_addr, target_addr, child) 
{
    subtype(CF_END_ACK);
}

Dot11EndCFAck::Dot11EndCFAck(const NetworkInterface &iface, 
  const address_type &dst_addr, const address_type &target_addr, PDU* child) 
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    subtype(CF_END_ACK);
}

Dot11EndCFAck::Dot11EndCFAck(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

PDU *Dot11EndCFAck::clone_pdu() const {
    Dot11EndCFAck *new_pdu = new Dot11EndCFAck();
    new_pdu->copy_80211_fields(this);
    return new_pdu;
}

/* Dot11Ack */

Dot11Ack::Dot11Ack(const address_type &dst_addr, PDU* child) 
: Dot11Control(dst_addr, child) 
{
    subtype(ACK);
}

Dot11Ack::Dot11Ack(const NetworkInterface &iface, 
  const address_type &dst_addr, PDU* child) 
: Dot11Control(iface, dst_addr, child) 
{
    subtype(ACK);
}

Dot11Ack::Dot11Ack(const uint8_t *buffer, uint32_t total_sz) : Dot11Control(buffer, total_sz) {

}

PDU *Dot11Ack::clone_pdu() const {
    Dot11Ack *ack = new Dot11Ack();
    ack->copy_80211_fields(this);
    return ack;
}

/* Dot11BlockAck */

Dot11BlockAckRequest::Dot11BlockAckRequest(
  const address_type &dst_addr , const address_type &target_addr, PDU* child) 
:  Dot11ControlTA(dst_addr, target_addr, child) 
{
    init_block_ack();
}

Dot11BlockAckRequest::Dot11BlockAckRequest(const NetworkInterface &iface, 
  const address_type &dst_addr, const address_type &target_addr, PDU* child)
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    init_block_ack();
}

Dot11BlockAckRequest::Dot11BlockAckRequest(const uint8_t *buffer, uint32_t total_sz) : Dot11ControlTA(buffer, total_sz) {
    uint32_t padding = controlta_size();
    buffer += padding;
    total_sz -= padding;
    if(total_sz < sizeof(_bar_control) + sizeof(_start_sequence))
        throw runtime_error("Not enough size for an IEEE 802.11 Block Ack frame in the buffer.");
    std::memcpy(&_bar_control, buffer, sizeof(_bar_control));
    buffer += sizeof(_bar_control);
    std::memcpy(&_start_sequence, buffer, sizeof(_start_sequence));
}

void Dot11BlockAckRequest::init_block_ack() {
    subtype(BLOCK_ACK_REQ);
    std::memset(&_bar_control, 0, sizeof(_bar_control));
    std::memset(&_start_sequence, 0, sizeof(_start_sequence));
}

uint32_t Dot11BlockAckRequest::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    uint32_t parent_size = Dot11ControlTA::write_ext_header(buffer, total_sz);
    buffer += parent_size;
    std::memcpy(buffer, &_bar_control, sizeof(_bar_control));
    buffer += sizeof(_bar_control);
    std::memcpy(buffer, &_start_sequence, sizeof(_start_sequence));
    return parent_size + sizeof(_start_sequence) + sizeof(_bar_control);
}

void Dot11BlockAckRequest::bar_control(uint16_t bar) {
    std::memcpy(&_bar_control, &bar, sizeof(bar));
}

void Dot11BlockAckRequest::start_sequence(uint16_t seq) {
    std::memcpy(&_start_sequence, &seq, sizeof(seq));
}

uint32_t Dot11BlockAckRequest::header_size() const {
    return Dot11ControlTA::header_size() + sizeof(_start_sequence) + sizeof(_start_sequence);
}

PDU *Dot11BlockAckRequest::clone_pdu() const {
    Dot11BlockAckRequest *new_pdu = new Dot11BlockAckRequest();
    new_pdu->copy_80211_fields(this);
    return new_pdu;
}

/* Dot11BlockAck */
Dot11BlockAck::Dot11BlockAck(const address_type &dst_addr, 
  const address_type &target_addr, PDU* child) 
:  Dot11ControlTA(dst_addr, target_addr, child) 
{
    subtype(BLOCK_ACK);
    std::memset(_bitmap, 0, sizeof(_bitmap));
}

Dot11BlockAck::Dot11BlockAck(const NetworkInterface &iface, 
  const address_type &dst_addr, const address_type &target_addr, PDU* child)
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    subtype(BLOCK_ACK);
    std::memset(_bitmap, 0, sizeof(_bitmap));
}

Dot11BlockAck::Dot11BlockAck(const uint8_t *buffer, uint32_t total_sz) : Dot11ControlTA(buffer, total_sz) {
    uint32_t padding = controlta_size();
    buffer += padding;
    total_sz -= padding;
    if(total_sz < sizeof(_bitmap) + sizeof(_bar_control) + sizeof(_start_sequence))
        throw runtime_error("Not enough size for an IEEE 802.11 Block Ack frame in the buffer.");
    std::memcpy(&_bar_control, buffer, sizeof(_bar_control));
    buffer += sizeof(_bar_control);
    std::memcpy(&_start_sequence, buffer, sizeof(_start_sequence));
    buffer += sizeof(_start_sequence);
    std::memcpy(&_bitmap, buffer, sizeof(_bitmap));
}

void Dot11BlockAck::bar_control(uint16_t bar) {
    std::memcpy(&_bar_control, &bar, sizeof(bar));
}

void Dot11BlockAck::start_sequence(uint16_t seq) {
    std::memcpy(&_start_sequence, &seq, sizeof(seq));
}

void Dot11BlockAck::bitmap(const uint8_t *bit) {
    std::memcpy(_bitmap, bit, sizeof(_bitmap));
}

uint32_t Dot11BlockAck::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    uint32_t parent_size = Dot11ControlTA::write_ext_header(buffer, total_sz);
    buffer += parent_size;
    std::memcpy(buffer, &_bar_control, sizeof(_bar_control));
    buffer += sizeof(_bar_control);
    std::memcpy(buffer, &_start_sequence, sizeof(_start_sequence));
    buffer += sizeof(_start_sequence);
    std::memcpy(buffer, _bitmap, sizeof(_bitmap));
    return parent_size + sizeof(_bitmap) + sizeof(_bar_control) + sizeof(_start_sequence);
}

uint32_t Dot11BlockAck::header_size() const {
    return Dot11ControlTA::header_size() + sizeof(_start_sequence) + sizeof(_start_sequence) + sizeof(_bitmap);
}

PDU *Dot11BlockAck::clone_pdu() const {
    Dot11BlockAck *new_pdu = new Dot11BlockAck();
    new_pdu->copy_80211_fields(this);
    return new_pdu;
}

/* RSNInformation */

RSNInformation::RSNInformation() : _version(1), _capabilities(0) {

}

void RSNInformation::add_pairwise_cypher(CypherSuites cypher) {
    _pairwise_cyphers.push_back(cypher);
}

void RSNInformation::add_akm_cypher(AKMSuites akm) {
    _akm_cyphers.push_back(akm);
}

void RSNInformation::group_suite(CypherSuites group) {
    _group_suite = group;
}

void RSNInformation::version(uint16_t ver) {
    _version = ver;
}

void RSNInformation::capabilities(uint16_t cap) {
    _capabilities = cap;
}

uint8_t *RSNInformation::serialize(uint32_t &size) const {
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

RSNInformation RSNInformation::wpa2_psk() {
    RSNInformation info;
    info.group_suite(RSNInformation::CCMP);
    info.add_pairwise_cypher(RSNInformation::CCMP);
    info.add_akm_cypher(RSNInformation::PSK);
    return info;
}
}
