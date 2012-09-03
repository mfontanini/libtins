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
#include "rsn_information.h"
#include "snap.h"

using std::pair;
using std::vector;
using std::string;
using std::list;
using std::runtime_error;

namespace Tins {
const Dot11::address_type Dot11::BROADCAST = "ff:ff:ff:ff:ff:ff";

Dot11::Dot11(const NetworkInterface &iface, 
  const address_type &dst_hw_addr, PDU* child) 
: PDU(ETHERTYPE_IP, child), _iface(iface), _options_size(0)
{
    memset(&_header, 0, sizeof(ieee80211_header));
    addr1(dst_hw_addr);
}

Dot11::Dot11(const ieee80211_header *header_ptr) 
: PDU(ETHERTYPE_IP) 
{

}

Dot11::Dot11(const uint8_t *buffer, uint32_t total_sz) 
: PDU(ETHERTYPE_IP), _options_size(0) 
{
    if(total_sz < sizeof(_header))
        throw runtime_error("Not enough size for an Dot11 header in the buffer.");
    std::memcpy(&_header, buffer, sizeof(_header));
}

void Dot11::parse_tagged_parameters(const uint8_t *buffer, uint32_t total_sz) {
    if(total_sz > 0) {
        uint8_t opcode, length;
        while(total_sz >= 2) {
            opcode = buffer[0];
            length = buffer[1];
            buffer += 2;
            total_sz -= 2;
            if(length > total_sz) {
                throw std::runtime_error("Malformed option encountered");
            }
            add_tagged_option((TaggedOption)opcode, length, buffer);
            buffer += length;
            total_sz -= length;
        }
    }
}

Dot11::Dot11Option::Dot11Option(uint8_t opt, uint8_t len, const uint8_t *val) 
: option_id(opt), value(val, val + len) {
    
}

void Dot11::add_tagged_option(TaggedOption opt, uint8_t len, const uint8_t *val) {
    uint32_t opt_size = len + (sizeof(uint8_t) << 1);
    _options.push_back(Dot11Option((uint8_t)opt, len, val));
    _options_size += opt_size;
}

const Dot11::Dot11Option *Dot11::search_option(TaggedOption opt) const {
    for(std::list<Dot11Option>::const_iterator it = _options.begin(); it != _options.end(); ++it)
        if(it->option() == (uint8_t)opt)
            return &(*it);
    return 0;
}

void Dot11::protocol(small_uint<2> new_proto) {
    this->_header.control.protocol = new_proto;
}

void Dot11::type(small_uint<2> new_type) {
    this->_header.control.type = new_type;
}

void Dot11::subtype(small_uint<4> new_subtype) {
    this->_header.control.subtype = new_subtype;
}

void Dot11::to_ds(small_uint<1> new_value) {
    this->_header.control.to_ds = (new_value)? 1 : 0;
}

void Dot11::from_ds(small_uint<1> new_value) {
    this->_header.control.from_ds = (new_value)? 1 : 0;
}

void Dot11::more_frag(small_uint<1> new_value) {
    this->_header.control.more_frag = (new_value)? 1 : 0;
}

void Dot11::retry(small_uint<1> new_value) {
    this->_header.control.retry = (new_value)? 1 : 0;
}

void Dot11::power_mgmt(small_uint<1> new_value) {
    this->_header.control.power_mgmt = (new_value)? 1 : 0;
}

void Dot11::wep(small_uint<1> new_value) {
    this->_header.control.wep = (new_value)? 1 : 0;
}

void Dot11::order(small_uint<1> new_value) {
    this->_header.control.order = (new_value)? 1 : 0;
}

void Dot11::duration_id(uint16_t new_duration_id) {
    this->_header.duration_id = Utils::host_to_le(new_duration_id);
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
    addr.sll_ifindex = _iface.id();
    memcpy(&(addr.sll_addr), _header.addr1, 6);

    return sender->send_l2(this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
}

void Dot11::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    uint32_t my_sz = header_size();
    assert(total_sz >= my_sz);
    memcpy(buffer, &_header, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);

    uint32_t written = write_ext_header(buffer, total_sz);
    buffer += written;
    total_sz -= written;

    uint32_t child_len = write_fixed_parameters(buffer, total_sz - _options_size);
    buffer += child_len;
    assert(total_sz >= child_len + _options_size);
    for(std::list<Dot11Option>::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        *(buffer++) = it->option();
        *(buffer++) = it->data_size();
        std::copy(it->data_ptr(), it->data_ptr() + it->data_size(), buffer);
        buffer += it->data_size();
    }
}

Dot11 *Dot11::from_bytes(const uint8_t *buffer, uint32_t total_sz) {
    // We only need the control field, the length of the PDU will depend on the flags set.
    if(total_sz < sizeof(ieee80211_header::control))
        throw runtime_error("Not enough size for a IEEE 802.11 header in the buffer.");
    const ieee80211_header *hdr = (const ieee80211_header*)buffer;
    Dot11 *ret = 0;
    if(hdr->control.type == MANAGEMENT) {
        if(hdr->control.subtype == BEACON)
            ret = new Dot11Beacon(buffer, total_sz);
        else if(hdr->control.subtype == DISASSOC)
            ret = new Dot11Disassoc(buffer, total_sz);
        else if(hdr->control.subtype == ASSOC_REQ)
            ret = new Dot11AssocRequest(buffer, total_sz);
        else if(hdr->control.subtype == ASSOC_RESP)
            ret = new Dot11AssocResponse(buffer, total_sz);
        else if(hdr->control.subtype == REASSOC_REQ)
            ret = new Dot11ReAssocRequest(buffer, total_sz);
        else if(hdr->control.subtype == REASSOC_RESP)
            ret = new Dot11ReAssocResponse(buffer, total_sz); 
        else if(hdr->control.subtype == AUTH)
            ret = new Dot11Authentication(buffer, total_sz); 
        else if(hdr->control.subtype == DEAUTH)
            ret = new Dot11Deauthentication(buffer, total_sz); 
        else if(hdr->control.subtype == PROBE_REQ)
            ret = new Dot11ProbeRequest(buffer, total_sz); 
        else if(hdr->control.subtype == PROBE_RESP)
            ret = new Dot11ProbeResponse(buffer, total_sz); 
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
    if(ret == 0)
        ret = new Dot11(buffer, total_sz);
    return ret;
}

void Dot11::copy_80211_fields(const Dot11 *other) {
    std::memcpy(&_header, &other->_header, sizeof(_header));
    _iface = other->_iface;
    _options_size = other->_options_size;
    for(std::list<Dot11Option>::const_iterator it = other->_options.begin(); it != other->_options.end(); ++it)
        _options.push_back(Dot11Option(it->option(), it->data_size(), it->data_ptr()));
}

/* Dot11ManagementFrame */

Dot11ManagementFrame::Dot11ManagementFrame(const uint8_t *buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz) 
{
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);
    if(total_sz < sizeof(_ext_header))
        throw runtime_error("Not enough size for an Dot11ManagementFrame header in the buffer.");
    std::memcpy(&_ext_header, buffer, sizeof(_ext_header));
    total_sz -= sizeof(_ext_header);
    if(from_ds() && to_ds()) {
        if(total_sz >= _addr4.size())
            _addr4 = buffer + sizeof(_ext_header);
        else
            throw runtime_error("Not enough size for an Dot11ManagementFrame header in the buffer.");        
    }
}

Dot11ManagementFrame::Dot11ManagementFrame(const NetworkInterface &iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11(iface, dst_hw_addr) 
{
    type(Dot11::MANAGEMENT);
    memset(&_ext_header, 0, sizeof(_ext_header));
    addr2(src_hw_addr);
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
    this->_ext_header.seq_control.seq_number = Utils::host_to_le(new_seq_num);
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
    RSNInformation::serialization_type buffer = info.serialize();
    add_tagged_option(RSN, buffer.size(), &buffer[0]);
}

uint8_t *Dot11ManagementFrame::serialize_rates(const rates_type &rates) {
    uint8_t *buffer = new uint8_t[rates.size()], *ptr = buffer;
    for(rates_type::const_iterator it = rates.begin(); it != rates.end(); ++it) {
        uint8_t result = *it * 2;
        if(result == 2 || result == 4 || result == 11 || result == 22)
            result |= 0x80;
        *(ptr++) = result;
    }
    return buffer;
}

Dot11ManagementFrame::rates_type Dot11ManagementFrame::deserialize_rates(const Dot11Option *option) {
    rates_type output;
    const uint8_t *ptr = option->data_ptr(), *end = ptr + option->data_size();
    while(ptr != end) {
        output.push_back(float(*(ptr++) & 0x7f) / 2);
    }
    return output;
}

void Dot11ManagementFrame::supported_rates(const rates_type &new_rates) {
    uint8_t *buffer = serialize_rates(new_rates);
    add_tagged_option(SUPPORTED_RATES, new_rates.size(), buffer);
    delete[] buffer;
}

void Dot11ManagementFrame::extended_supported_rates(const rates_type &new_rates) {
    uint8_t *buffer = serialize_rates(new_rates);
    add_tagged_option(EXT_SUPPORTED_RATES, new_rates.size(), buffer);
    delete[] buffer;
}

void Dot11ManagementFrame::qos_capability(uint8_t new_qos_capability) {
    add_tagged_option(QOS_CAPABILITY, 1, &new_qos_capability);
}

void Dot11ManagementFrame::power_capability(uint8_t min_power, uint8_t max_power) {
    uint8_t buffer[2];
    buffer[0] = min_power;
    buffer[1] = max_power;
    add_tagged_option(POWER_CAPABILITY, 2, buffer);
}

void Dot11ManagementFrame::supported_channels(const channels_type &new_channels) {
    uint8_t* buffer = new uint8_t[new_channels.size() * 2];
    uint8_t* ptr = buffer;
    for(channels_type::const_iterator it = new_channels.begin(); it != new_channels.end(); ++it) {
        *(ptr++) = it->first;
        *(ptr++) = it->second;
    }
    add_tagged_option(SUPPORTED_CHANNELS, new_channels.size() * 2, buffer);
    delete[] buffer;
}

void Dot11ManagementFrame::edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo) {
    uint8_t buffer[18];
    buffer[0] = 0;
    buffer[1] = 0;
    uint32_t* ptr = (uint32_t*)(buffer + 2);
    *(ptr++) = Utils::host_to_le(ac_be);
    *(ptr++) = Utils::host_to_le(ac_bk);
    *(ptr++) = Utils::host_to_le(ac_vi);
    *(ptr++) = Utils::host_to_le(ac_vo);
    add_tagged_option(EDCA, sizeof(buffer), buffer);
}

void Dot11ManagementFrame::request_information(const request_info_type elements) {
    uint8_t *buffer = new uint8_t[elements.size()], *ptr = buffer;
    for (request_info_type::const_iterator it = elements.begin(); it != elements.end(); ++it)
        *(ptr++) = *it;
    add_tagged_option(REQUEST_INFORMATION, elements.size(), buffer);
    delete[] buffer;
}

void Dot11ManagementFrame::fh_parameter_set(fh_params_set fh_params) {
    fh_params.dwell_time = Utils::host_to_le(fh_params.dwell_time);
    fh_params.hop_set = fh_params.hop_set;
    fh_params.hop_pattern = fh_params.hop_pattern;
    fh_params.hop_index = fh_params.hop_index;
    add_tagged_option(FH_SET, sizeof(fh_params_set), (uint8_t*)&fh_params);

}

void Dot11ManagementFrame::ds_parameter_set(uint8_t current_channel) {
    add_tagged_option(DS_SET, 1, &current_channel);
}

void Dot11ManagementFrame::cf_parameter_set(cf_params_set params) {
    params.cfp_count = params.cfp_count;
    params.cfp_period = params.cfp_period;
    params.cfp_max_duration = Utils::host_to_le(params.cfp_max_duration);
    params.cfp_dur_remaining = Utils::host_to_le(params.cfp_dur_remaining);
    add_tagged_option(CF_SET, sizeof(params), (uint8_t*)&params);
}

void Dot11ManagementFrame::ibss_parameter_set(uint16_t atim_window) {
    atim_window = Utils::host_to_le(atim_window);
    add_tagged_option(IBSS_SET, 2, (uint8_t*)&atim_window);
}

void Dot11ManagementFrame::ibss_dfs(const ibss_dfs_params &params) {
    uint8_t sz = address_type::address_size + sizeof(uint8_t) + sizeof(uint8_t) * 2 * params.channel_map.size();
    uint8_t* buffer = new uint8_t[sz];
    uint8_t* ptr_buffer = buffer;

    ptr_buffer = params.dfs_owner.copy(ptr_buffer);
    *(ptr_buffer++) = params.recovery_interval;
    for (channels_type::const_iterator it = params.channel_map.begin(); it != params.channel_map.end(); ++it) {
        *(ptr_buffer++) = it->first;
        *(ptr_buffer++) = it->second;
    }

    add_tagged_option(IBSS_DFS, sz, buffer);

    delete[] buffer;
}

void Dot11ManagementFrame::country(const country_params &params) {
    if ((params.first_channel.size() != params.number_channels.size()) ||
        (params.number_channels.size() != params.max_transmit_power.size()))
        throw runtime_error("The length of the lists are distinct");
    if(params.country.size() != 3)
        throw runtime_error("Invalid country identifier length");
    size_t sz = sizeof(uint8_t) * 3 * params.first_channel.size() + params.country.size();
    // Use 1 byte padding at the end if the length is odd.
    if((sz & 1) == 1)
        sz++;
    std::vector<uint8_t> buffer(sz);
    uint8_t *ptr = std::copy(params.country.begin(), params.country.end(), &buffer[0]);
    for(size_t i(0); i < params.first_channel.size(); ++i) {
        *(ptr++) = params.first_channel[i];
        *(ptr++) = params.number_channels[i];
        *(ptr++) = params.max_transmit_power[i];
    }
    add_tagged_option(COUNTRY, sz, &buffer[0]);
}

void Dot11ManagementFrame::fh_parameters(uint8_t prime_radix, uint8_t number_channels) {
    uint8_t buffer[2];
    buffer[0] = prime_radix;
    buffer[1] = number_channels;
    add_tagged_option(HOPPING_PATTERN_PARAMS, 2, buffer);
}

void Dot11ManagementFrame::fh_pattern_table(const fh_pattern_type &params) {
    std::vector<uint8_t> data(sizeof(uint8_t) * 4 + params.random_table.size());
    uint8_t *ptr = &data[0];
    *(ptr++) = params.flag;
    *(ptr++) = params.number_of_sets;
    *(ptr++) = params.modulus;
    *(ptr++) = params.offset;
    fh_pattern_type::container_type::const_iterator it(params.random_table.begin());
    for(; it != params.random_table.end(); ++it)
        *(ptr++) = *it;
    add_tagged_option(HOPPING_PATTERN_TABLE, data.size(), &data[0]);
}

void Dot11ManagementFrame::power_constraint(uint8_t local_power_constraint) {
    add_tagged_option(POWER_CONSTRAINT, 1, &local_power_constraint);
}

void Dot11ManagementFrame::channel_switch(const channel_switch_type &data) {
    uint8_t buffer[3];
    buffer[0] = data.switch_mode;
    buffer[1] = data.new_channel;
    buffer[2] = data.switch_count;
    add_tagged_option(CHANNEL_SWITCH, 3, buffer);

}

void Dot11ManagementFrame::quiet(const quiet_type &data) {
    uint8_t buffer[6];
    uint16_t* ptr_buffer = (uint16_t*)(buffer + 2);

    buffer[0] = data.quiet_count;
    buffer[1] = data.quiet_period;
    ptr_buffer[0] = Utils::host_to_le(data.quiet_duration);
    ptr_buffer[1] = Utils::host_to_le(data.quiet_offset);
    add_tagged_option(QUIET, sizeof(buffer), buffer);

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

void Dot11ManagementFrame::bss_load(const bss_load_type &data) {
    uint8_t buffer[5];

    *(uint16_t*)buffer = Utils::host_to_le(data.station_count);
    buffer[2] = data.channel_utilization;
    *(uint16_t*)(buffer + 3) = Utils::host_to_le(data.available_capacity);
    add_tagged_option(BSS_LOAD, sizeof(buffer), buffer);
}

void Dot11ManagementFrame::tim(const tim_type &data) {
    std::vector<uint8_t> buffer(sizeof(uint8_t) * 3 + data.partial_virtual_bitmap.size());
    buffer[0] = data.dtim_count;
    buffer[1] = data.dtim_period;
    buffer[2] = data.bitmap_control;
    std::copy(
        data.partial_virtual_bitmap.begin(), 
        data.partial_virtual_bitmap.end(),
        &buffer[3]
    );
    add_tagged_option(TIM, buffer.size(), &buffer[0]);
}

void Dot11ManagementFrame::challenge_text(const std::string &text) {
    add_tagged_option(
        CHALLENGE_TEXT, 
        text.size(),
        (const uint8_t*)text.c_str()
    );
}

// Getters

RSNInformation Dot11ManagementFrame::rsn_information() {
    const Dot11::Dot11Option *option = search_option(RSN);
    if(!option || option->data_size() < (sizeof(uint16_t) << 1) + sizeof(uint32_t))
        throw std::runtime_error("RSN information not set");
    return RSNInformation(option->data_ptr(), option->data_size());
}

string Dot11ManagementFrame::ssid() const {
    const Dot11::Dot11Option *option = search_option(SSID);
    if(!option || option->data_size() == 0)
        throw std::runtime_error("SSID not set");
    return string((const char*)option->data_ptr(), option->data_size());
}

Dot11ManagementFrame::rates_type Dot11ManagementFrame::supported_rates() const {
    const Dot11::Dot11Option *option = search_option(SUPPORTED_RATES);
    if(!option || option->data_size() == 0)
        throw std::runtime_error("Supported rates not set");
    return deserialize_rates(option);
}

Dot11ManagementFrame::rates_type Dot11ManagementFrame::extended_supported_rates() const {
    const Dot11::Dot11Option *option = search_option(EXT_SUPPORTED_RATES);
    if(!option || option->data_size() == 0)
        throw std::runtime_error("Extended supported rates not set");
    return deserialize_rates(option);
}

uint8_t Dot11ManagementFrame::qos_capability() const {
    const Dot11::Dot11Option *option = search_option(QOS_CAPABILITY);
    if(!option || option->data_size() != 1)
        throw std::runtime_error("QOS capability not set");
    return *option->data_ptr();
}

std::pair<uint8_t, uint8_t> Dot11ManagementFrame::power_capability() const {
    const Dot11::Dot11Option *option = search_option(POWER_CAPABILITY);
    if(!option || option->data_size() != 2)
        throw std::runtime_error("Power capability not set");
    return std::make_pair(*option->data_ptr(), *(option->data_ptr() + 1));
}

Dot11ManagementFrame::channels_type Dot11ManagementFrame::supported_channels() const {
    const Dot11::Dot11Option *option = search_option(SUPPORTED_CHANNELS);
    // We need a multiple of two
    if(!option || ((option->data_size() & 0x1) == 1))
        throw std::runtime_error("Supported channels not set");
    channels_type output;
    const uint8_t *ptr = option->data_ptr(), *end = ptr + option->data_size();
    while(ptr != end) {
        uint8_t first = *(ptr++);
        output.push_back(std::make_pair(first, *(ptr++)));
    }
    return output;
}

Dot11ManagementFrame::request_info_type Dot11ManagementFrame::request_information() const {
    const Dot11::Dot11Option *option = search_option(REQUEST_INFORMATION);
    if(!option || option->data_size() == 0)
        throw std::runtime_error("Request information not set");
    request_info_type output;
    const uint8_t *ptr = option->data_ptr(), *end = ptr + option->data_size();
    output.assign(ptr, end);
    return output;
}

Dot11ManagementFrame::fh_params_set Dot11ManagementFrame::fh_parameter_set() const {
    const Dot11::Dot11Option *option = search_option(FH_SET);
    if(!option || option->data_size() != sizeof(fh_params_set))
        throw std::runtime_error("FH parameters set not set");
    fh_params_set output = *reinterpret_cast<const fh_params_set*>(option->data_ptr());
    output.dwell_time = Utils::le_to_host(output.dwell_time);
    output.hop_set = output.hop_set;
    output.hop_pattern = output.hop_pattern;
    output.hop_index = output.hop_index;
    return output;
}

uint8_t Dot11ManagementFrame::ds_parameter_set() const {
    const Dot11::Dot11Option *option = search_option(DS_SET);
    if(!option || option->data_size() != sizeof(uint8_t))
        throw std::runtime_error("DS parameters set not set");
    return *option->data_ptr();
}

uint16_t Dot11ManagementFrame::ibss_parameter_set() const {
    const Dot11::Dot11Option *option = search_option(IBSS_SET);
    if(!option || option->data_size() != sizeof(uint16_t))
        throw std::runtime_error("IBSS parameters set not set");
    return Utils::le_to_host(*reinterpret_cast<const uint16_t*>(option->data_ptr()));
}

Dot11ManagementFrame::ibss_dfs_params Dot11ManagementFrame::ibss_dfs() const {
    const Dot11::Dot11Option *option = search_option(IBSS_DFS);
    if(!option || option->data_size() < ibss_dfs_params::minimum_size)
        throw std::runtime_error("IBSS DFS set not set");
    ibss_dfs_params output;
    const uint8_t *ptr = option->data_ptr(), *end = ptr + option->data_size();
    output.dfs_owner = ptr;
    ptr += output.dfs_owner.size();
    output.recovery_interval = *(ptr++);
    while(ptr != end) {
        uint8_t first = *(ptr++);
        if(ptr == end)
            throw std::runtime_error("Malformed channel data");
        output.channel_map.push_back(std::make_pair(first, *(ptr++)));
    }
    return output;
}

Dot11ManagementFrame::country_params Dot11ManagementFrame::country() const {
    const Dot11::Dot11Option *option = search_option(COUNTRY);
    if(!option || option->data_size() < country_params::minimum_size)
        throw std::runtime_error("Country option not set");
    country_params output;
    const uint8_t *ptr = option->data_ptr(), *end = ptr + option->data_size();
    std::copy(ptr, ptr + 3, std::back_inserter(output.country));
    ptr += output.country.size();
    while(end - ptr >= 3) {
        output.first_channel.push_back(*(ptr++));
        output.number_channels.push_back(*(ptr++));
        output.max_transmit_power.push_back(*(ptr++));
    }
    if(ptr != end)
        throw std::runtime_error("Malformed option");
    return output;
}

std::pair<uint8_t, uint8_t> Dot11ManagementFrame::fh_parameters() const {
    const Dot11::Dot11Option *option = search_option(HOPPING_PATTERN_PARAMS);
    if(!option || option->data_size() != sizeof(uint8_t) * 2)
        throw std::runtime_error("FH parameters option not set");
    const uint8_t *ptr = option->data_ptr();
    uint8_t first = *(ptr++);
    return std::make_pair(first, *ptr);
}

Dot11ManagementFrame::fh_pattern_type Dot11ManagementFrame::fh_pattern_table() const {
    const Dot11::Dot11Option *option = search_option(HOPPING_PATTERN_TABLE);
    if(!option || option->data_size() < fh_pattern_type::minimum_size)
        throw std::runtime_error("FH pattern option not set");
    fh_pattern_type output;
    const uint8_t *ptr = option->data_ptr(), *end = ptr + option->data_size();
    
    output.flag = *(ptr++);
    output.number_of_sets = *(ptr++);
    output.modulus = *(ptr++);
    output.offset = *(ptr++);
    
    output.random_table.assign(ptr, end);
    return output;
}

uint8_t Dot11ManagementFrame::power_constraint() const {
    const Dot11::Dot11Option *option = search_option(POWER_CONSTRAINT);
    if(!option || option->data_size() != 1)
        throw std::runtime_error("Power constraint option not set");
    return *option->data_ptr();
}

Dot11ManagementFrame::channel_switch_type Dot11ManagementFrame::channel_switch() const {
    const Dot11::Dot11Option *option = search_option(CHANNEL_SWITCH);
    if(!option || option->data_size() != sizeof(uint8_t) * 3)
        throw std::runtime_error("Channel switch option not set");
    const uint8_t *ptr = option->data_ptr();
    channel_switch_type output;
    output.switch_mode = *(ptr++);
    output.new_channel = *(ptr++);
    output.switch_count = *(ptr++);
    return output;
}

Dot11ManagementFrame::quiet_type Dot11ManagementFrame::quiet() const {
    const Dot11::Dot11Option *option = search_option(QUIET);
    if(!option || option->data_size() != (sizeof(uint8_t) * 2 + sizeof(uint16_t) * 2))
        throw std::runtime_error("Quiet option not set");
    const uint8_t *ptr = option->data_ptr();
    quiet_type output;
    
    output.quiet_count = *(ptr++);
    output.quiet_period = *(ptr++);
    const uint16_t *ptr_16 = (const uint16_t*)ptr;
    output.quiet_duration = Utils::le_to_host(*(ptr_16++));
    output.quiet_offset = Utils::le_to_host(*ptr_16);
    return output;
}

std::pair<uint8_t, uint8_t> Dot11ManagementFrame::tpc_report() const {
    const Dot11::Dot11Option *option = search_option(TPC_REPORT);
    if(!option || option->data_size() != sizeof(uint8_t) * 2)
        throw std::runtime_error("TPC Report option not set");
    const uint8_t *ptr = option->data_ptr();
    uint8_t first = *(ptr++);
    return std::make_pair(first, *ptr);
}

uint8_t Dot11ManagementFrame::erp_information() const {
    const Dot11::Dot11Option *option = search_option(ERP_INFORMATION);
    if(!option || option->data_size() != sizeof(uint8_t))
        throw std::runtime_error("ERP Information option not set");
    return *option->data_ptr();
}

Dot11ManagementFrame::bss_load_type Dot11ManagementFrame::bss_load() const {
    const Dot11::Dot11Option *option = search_option(BSS_LOAD);
    if(!option || option->data_size() != sizeof(uint8_t) + 2 * sizeof(uint16_t))
        throw std::runtime_error("BSS Load option not set");
    bss_load_type output;
    
    const uint8_t *ptr = option->data_ptr();
    output.station_count = Utils::le_to_host(*(uint16_t*)ptr);
    output.channel_utilization = ptr[2];
    output.available_capacity = Utils::le_to_host(*(uint16_t*)(ptr + 3));
    return output;
}

Dot11ManagementFrame::tim_type Dot11ManagementFrame::tim() const {
    const Dot11::Dot11Option *option = search_option(TIM);
    if(!option || option->data_size() < 4 * sizeof(uint8_t))
        throw std::runtime_error("TIM option not set");
    const uint8_t *ptr = option->data_ptr(), *end = ptr + option->data_size();
    tim_type output;
    
    output.dtim_count = *(ptr++);
    output.dtim_period = *(ptr++);
    output.bitmap_control = *(ptr++);
    
    output.partial_virtual_bitmap.assign(ptr, end);
    return output;
}

std::string Dot11ManagementFrame::challenge_text() const {
    const Dot11::Dot11Option *option = search_option(CHALLENGE_TEXT);
    if(!option || option->data_size() == 0)
        throw std::runtime_error("Challenge text option not set");
    return std::string(option->data_ptr(), option->data_ptr() + option->data_size());
}

/* Dot11Beacon */

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
    this->_body.timestamp = Utils::host_to_le(new_timestamp);
}

void Dot11Beacon::interval(uint16_t new_interval) {
    this->_body.interval = Utils::host_to_le(new_interval);
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

/* Diassoc */

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
    this->_body.reason_code = Utils::host_to_le(new_reason_code);
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

/* Assoc request. */

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
    this->_body.listen_interval = Utils::host_to_le(new_listen_interval);
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

/* Assoc response. */

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
    this->_body.status_code = Utils::host_to_le(new_status_code);
}

void Dot11AssocResponse::aid(uint16_t new_aid) {
    this->_body.aid = Utils::host_to_le(new_aid);
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

/* ReAssoc request. */

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
    this->_body.listen_interval = Utils::host_to_le(new_listen_interval);
}

void Dot11ReAssocRequest::current_ap(const address_type &new_current_ap) {
    new_current_ap.copy(_body.current_ap);
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

/* ReAssoc response. */

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
    this->_body.status_code = Utils::host_to_le(new_status_code);
}

void Dot11ReAssocResponse::aid(uint16_t new_aid) {
    this->_body.aid = Utils::host_to_le(new_aid);
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


/* Auth */

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
    this->_body.auth_algorithm = Utils::host_to_le(new_auth_algorithm);
}

void Dot11Authentication::auth_seq_number(uint16_t new_auth_seq_number) {
    this->_body.auth_seq_number = Utils::host_to_le(new_auth_seq_number);
}

void Dot11Authentication::status_code(uint16_t new_status_code) {
    this->_body.status_code = Utils::host_to_le(new_status_code);
}

uint32_t Dot11Authentication::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(_body);
}

uint32_t Dot11Authentication::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
}

/* Deauth */

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
    this->_body.reason_code = Utils::host_to_le(new_reason_code);
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

/* Probe Request */

Dot11ProbeRequest::Dot11ProbeRequest(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::PROBE_REQ);
}

Dot11ProbeRequest::Dot11ProbeRequest(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ManagementFrame(buffer, total_sz) 
{
    uint32_t sz = management_frame_size();
    buffer += sz;
    total_sz -= sz;
    parse_tagged_parameters(buffer, total_sz);
}

/* Probe Response */

Dot11ProbeResponse::Dot11ProbeResponse(const NetworkInterface& iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr) 
: Dot11ManagementFrame(iface, dst_hw_addr, src_hw_addr) 
{
    this->subtype(Dot11::PROBE_RESP);
    memset(&_body, 0, sizeof(_body));
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
    this->_body.timestamp = Utils::host_to_le(new_timestamp);
}

void Dot11ProbeResponse::interval(uint16_t new_interval) {
    this->_body.interval = Utils::host_to_le(new_interval);
}

uint32_t Dot11ProbeResponse::header_size() const {
    return Dot11ManagementFrame::header_size() + sizeof(this->_body);
}

uint32_t Dot11ProbeResponse::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_body);
    assert(sz <= total_sz);
    memcpy(buffer, &this->_body, sz);
    return sz;
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
        if(total_sz < _addr4.size())
            throw runtime_error("Not enough size for an IEEE 802.11 data header in the buffer.");
        _addr4 = buffer;
        buffer += _addr4.size();
        total_sz -= _addr4.size();
    }
    if(total_sz)
        inner_pdu(new Tins::SNAP(buffer, total_sz));
}


Dot11Data::Dot11Data(const NetworkInterface &iface,
  const address_type &dst_hw_addr, const address_type &src_hw_addr,
  PDU* child) 
: Dot11(iface, dst_hw_addr, child) 
{
    type(Dot11::DATA);
    memset(&_ext_header, 0, sizeof(_ext_header));
    addr2(src_hw_addr);
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
    _ext_header.seq_control.frag_number = new_frag_num;
}

void Dot11Data::seq_num(uint16_t new_seq_num) {
    _ext_header.seq_control.seq_number = Utils::host_to_le(new_seq_num);
}

void Dot11Data::addr4(const address_type &new_addr4) {
    _addr4 = new_addr4;
}

uint32_t Dot11Data::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    uint32_t written = sizeof(_ext_header);
    memcpy(buffer, &_ext_header, sizeof(_ext_header));
    buffer += sizeof(_ext_header);
    if (from_ds() && to_ds()) {
        written += _addr4.size();
        _addr4.copy(buffer);
    }
    return written;

}

/* QoS data. */

Dot11QoSData::Dot11QoSData(const NetworkInterface &iface, 
  const address_type &dst_hw_addr, const address_type &src_hw_addr, 
  PDU* child) 
: Dot11Data(iface, dst_hw_addr, src_hw_addr, child) 
{
    subtype(Dot11::QOS_DATA_DATA);
    _qos_control = 0;
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
    _qos_control = *(uint16_t*)buffer;
    total_sz -= sizeof(uint16_t);
    buffer += sizeof(uint16_t);
    if(total_sz)
        inner_pdu(new Tins::SNAP(buffer, total_sz));
}

void Dot11QoSData::qos_control(uint16_t new_qos_control) {
    this->_qos_control = Utils::host_to_le(new_qos_control);
}

uint32_t Dot11QoSData::header_size() const {
    return Dot11Data::header_size() + sizeof(this->_qos_control);
}

uint32_t Dot11QoSData::write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = sizeof(this->_qos_control);
    assert(sz <= total_sz);
    *(uint16_t*)buffer = this->_qos_control;
    return sz;
}

/* Dot11Control */

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
    //std::memcpy(_taddr, buffer, sizeof(_taddr));
    _taddr = buffer;
}

uint32_t Dot11ControlTA::header_size() const {
    return Dot11::header_size() + sizeof(_taddr);
}

uint32_t Dot11ControlTA::write_ext_header(uint8_t *buffer, uint32_t total_sz) {
    assert(total_sz >= sizeof(_taddr));
    //std::memcpy(buffer, _taddr, sizeof(_taddr));
    _taddr.copy(buffer);
    return sizeof(_taddr);
}

void Dot11ControlTA::target_addr(const address_type &addr) {
    _taddr = addr;
}

/* Dot11RTS */

Dot11RTS::Dot11RTS(const NetworkInterface &iface, const address_type &dst_addr, 
  const address_type &target_addr, PDU* child) 
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    subtype(RTS);
}

Dot11RTS::Dot11RTS(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

/* Dot11PSPoll */

Dot11PSPoll::Dot11PSPoll(const NetworkInterface &iface, 
  const address_type &dst_addr, const address_type &target_addr, PDU* child) 
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    subtype(PS);
}

Dot11PSPoll::Dot11PSPoll(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

/* Dot11CFEnd */

Dot11CFEnd::Dot11CFEnd(const NetworkInterface &iface, 
  const address_type &dst_addr, const address_type &target_addr, PDU* child) 
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    subtype(CF_END);
}

Dot11CFEnd::Dot11CFEnd(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

/* Dot11EndCFAck */

Dot11EndCFAck::Dot11EndCFAck(const NetworkInterface &iface, 
  const address_type &dst_addr, const address_type &target_addr, PDU* child) 
: Dot11ControlTA(iface, dst_addr, target_addr, child) 
{
    subtype(CF_END_ACK);
}

Dot11EndCFAck::Dot11EndCFAck(const uint8_t *buffer, uint32_t total_sz) 
: Dot11ControlTA(buffer, total_sz) {

}

/* Dot11Ack */

Dot11Ack::Dot11Ack(const NetworkInterface &iface, 
  const address_type &dst_addr, PDU* child) 
: Dot11Control(iface, dst_addr, child) 
{
    subtype(ACK);
}

Dot11Ack::Dot11Ack(const uint8_t *buffer, uint32_t total_sz) : Dot11Control(buffer, total_sz) {

}

/* Dot11BlockAck */

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
    //std::memcpy(&_bar_control, &bar, sizeof(bar));
    _bar_control.tid = Utils::host_to_le(bar);
}

void Dot11BlockAckRequest::start_sequence(uint16_t seq) {
    //std::memcpy(&_start_sequence, &seq, sizeof(seq));
    _start_sequence.seq = Utils::host_to_le(seq);
}

void Dot11BlockAckRequest::fragment_number(uint8_t frag) {
    _start_sequence.frag = frag;
}

uint32_t Dot11BlockAckRequest::header_size() const {
    return Dot11ControlTA::header_size() + sizeof(_start_sequence) + sizeof(_start_sequence);
}

/* Dot11BlockAck */

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

}
