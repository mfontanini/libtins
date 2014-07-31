/*
 * Copyright (c) 2014, Matias Fontanini
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

#include "dot11/dot11_mgmt.h"
#ifdef HAVE_DOT11

#include <cstring>
#include "rsn_information.h"

namespace Tins {
/* Dot11ManagementFrame */

Dot11ManagementFrame::Dot11ManagementFrame(const uint8_t *buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz) 
{
    buffer += sizeof(ieee80211_header);
    total_sz -= sizeof(ieee80211_header);
    if(total_sz < sizeof(_ext_header))
        throw malformed_packet();
    std::memcpy(&_ext_header, buffer, sizeof(_ext_header));
    total_sz -= sizeof(_ext_header);
    if(from_ds() && to_ds()) {
        if(total_sz >= _addr4.size())
            _addr4 = buffer + sizeof(_ext_header);
        else
            throw malformed_packet();
    }
}

Dot11ManagementFrame::Dot11ManagementFrame(const address_type &dst_hw_addr, 
const address_type &src_hw_addr) 
: Dot11(dst_hw_addr) 
{
    type(Dot11::MANAGEMENT);
    memset(&_ext_header, 0, sizeof(_ext_header));
    addr2(src_hw_addr);
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

void Dot11ManagementFrame::frag_num(small_uint<4> new_frag_num) {
    #if TINS_IS_LITTLE_ENDIAN
    _ext_header.frag_seq = new_frag_num | (_ext_header.frag_seq & 0xfff0);
    #else
    _ext_header.frag_seq = (new_frag_num << 8) | (_ext_header.frag_seq & 0xf0ff);
    #endif
}

void Dot11ManagementFrame::seq_num(small_uint<12> new_seq_num) {
    #if TINS_IS_LITTLE_ENDIAN
    _ext_header.frag_seq = (new_seq_num << 4) | (_ext_header.frag_seq & 0xf);
    #else
    _ext_header.frag_seq = Endian::host_to_le<uint16_t>(new_seq_num << 4) | (_ext_header.frag_seq & 0xf00);
    #endif
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
        uint8_t result = static_cast<uint8_t>(*it * 2);
        if(result == 2 || result == 4 || result == 11 || result == 22)
            result |= 0x80;
        *(ptr++) = result;
    }
    return buffer;
}

Dot11ManagementFrame::rates_type Dot11ManagementFrame::deserialize_rates(const option *opt) {
    rates_type output;
    const uint8_t *ptr = opt->data_ptr(), *end = ptr + opt->data_size();
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

void Dot11ManagementFrame::qos_capability(qos_capability_type new_qos_capability) {
    add_tagged_option(QOS_CAPABILITY, 1, &new_qos_capability);
}

void Dot11ManagementFrame::power_capability(uint8_t min_power, uint8_t max_power) {
    uint8_t buffer[2];
    buffer[0] = min_power;
    buffer[1] = max_power;
    add_tagged_option(POWER_CAPABILITY, 2, buffer);
}

void Dot11ManagementFrame::supported_channels(const channels_type &new_channels) {
    std::vector<uint8_t> buffer(new_channels.size() * 2);
    uint8_t* ptr = &buffer[0];
    for(channels_type::const_iterator it = new_channels.begin(); it != new_channels.end(); ++it) {
        *(ptr++) = it->first;
        *(ptr++) = it->second;
    }
    add_tagged_option(SUPPORTED_CHANNELS, buffer.size(), &buffer[0]);
}

void Dot11ManagementFrame::edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo) {
    uint8_t buffer[18];
    buffer[0] = 0;
    buffer[1] = 0;
    uint32_t* ptr = (uint32_t*)(buffer + 2);
    *(ptr++) = Endian::host_to_le(ac_be);
    *(ptr++) = Endian::host_to_le(ac_bk);
    *(ptr++) = Endian::host_to_le(ac_vi);
    *(ptr++) = Endian::host_to_le(ac_vo);
    add_tagged_option(EDCA, sizeof(buffer), buffer);
}

void Dot11ManagementFrame::request_information(const request_info_type elements) {
    add_tagged_option(REQUEST_INFORMATION, elements.size(), &elements[0]);
}

void Dot11ManagementFrame::fh_parameter_set(const fh_params_set &fh_params) {
    uint8_t data[5];
    uint16_t dwell = Endian::host_to_le(fh_params.dwell_time);
    std::memcpy(data, &dwell, sizeof(dwell));
    data[2] = fh_params.hop_set;
    data[3] = fh_params.hop_pattern;
    data[4] = fh_params.hop_index;
    add_tagged_option(FH_SET, sizeof(data), data);

}

void Dot11ManagementFrame::ds_parameter_set(uint8_t current_channel) {
    add_tagged_option(DS_SET, 1, &current_channel);
}

void Dot11ManagementFrame::cf_parameter_set(const cf_params_set &params) {
    uint8_t data[6];
    data[0] = params.cfp_count;
    data[1] = params.cfp_period;
    uint16_t dummy = Endian::host_to_le(params.cfp_max_duration);
    std::memcpy(data + 2, &dummy, sizeof(uint16_t));
    dummy = Endian::host_to_le(params.cfp_dur_remaining);
    std::memcpy(data + 4, &dummy, sizeof(uint16_t));
    add_tagged_option(CF_SET, sizeof(data), data);
}

void Dot11ManagementFrame::ibss_parameter_set(uint16_t atim_window) {
    atim_window = Endian::host_to_le(atim_window);
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
        throw std::runtime_error("The length of the lists are distinct");
    if(params.country.size() != 3)
        throw std::runtime_error("Invalid country identifier length");
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
    byte_array::const_iterator it(params.random_table.begin());
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
    ptr_buffer[0] = Endian::host_to_le(data.quiet_duration);
    ptr_buffer[1] = Endian::host_to_le(data.quiet_offset);
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
    uint16_t dummy = Endian::host_to_le(data.station_count);

    //*(uint16_t*)buffer = Endian::host_to_le(data.station_count);
    #if TINS_IS_LITTLE_ENDIAN
    buffer[0] = dummy & 0xff;
    buffer[1] = (dummy >> 8) & 0xff;
    #else
    buffer[0] = (dummy >> 8) & 0xff;
    buffer[1] = dummy & 0xff;
    #endif
    buffer[2] = data.channel_utilization;
    dummy = Endian::host_to_le(data.available_capacity);
    #if TINS_IS_LITTLE_ENDIAN
    buffer[3] = dummy & 0xff;
    buffer[4] = (dummy >> 8) & 0xff;
    #else
    buffer[3] = (dummy >> 8) & 0xff;
    buffer[4] = dummy & 0xff;
    #endif
    //*(uint16_t*)(buffer + 3) = Endian::host_to_le(data.available_capacity);
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

void Dot11ManagementFrame::vendor_specific(const vendor_specific_type &data) {
    byte_array buffer(3 + data.data.size());
    std::copy(
        data.data.begin(),
        data.data.end(),
        data.oui.copy(buffer.begin())
    );
    add_tagged_option(VENDOR_SPECIFIC, buffer.size(), &buffer[0]);
}

// Getters

RSNInformation Dot11ManagementFrame::rsn_information() {
    return search_and_convert<RSNInformation>(RSN);
}

std::string Dot11ManagementFrame::ssid() const {
    const Dot11::option *option = search_option(SSID);
    if(!option)
        throw option_not_found();
    if(option->data_size() == 0 && this->subtype() == Dot11::PROBE_REQ)
        return "BROADCAST";
    else 
        return std::string((const char*)option->data_ptr(), option->data_size());
}

Dot11ManagementFrame::rates_type Dot11ManagementFrame::supported_rates() const {
    return search_and_convert<rates_type>(SUPPORTED_RATES);
}

Dot11ManagementFrame::rates_type Dot11ManagementFrame::extended_supported_rates() const {
    return search_and_convert<rates_type>(EXT_SUPPORTED_RATES);
}

Dot11ManagementFrame::qos_capability_type Dot11ManagementFrame::qos_capability() const {
    return search_and_convert<uint8_t>(QOS_CAPABILITY);
}

std::pair<uint8_t, uint8_t> Dot11ManagementFrame::power_capability() const {
    return search_and_convert<std::pair<uint8_t, uint8_t> >(POWER_CAPABILITY);
}

Dot11ManagementFrame::channels_type Dot11ManagementFrame::supported_channels() const {
    return search_and_convert<channels_type>(SUPPORTED_CHANNELS);
}

Dot11ManagementFrame::request_info_type Dot11ManagementFrame::request_information() const {
    return search_and_convert<request_info_type>(REQUEST_INFORMATION);
}

Dot11ManagementFrame::fh_params_set Dot11ManagementFrame::fh_parameter_set() const {
    return search_and_convert<fh_params_set>(FH_SET);
}

uint8_t Dot11ManagementFrame::ds_parameter_set() const {
    return search_and_convert<uint8_t>(DS_SET);
}

Dot11ManagementFrame::cf_params_set Dot11ManagementFrame::cf_parameter_set() const {
    return search_and_convert<cf_params_set>(CF_SET);
}

uint16_t Dot11ManagementFrame::ibss_parameter_set() const {
    return search_and_convert<uint16_t>(IBSS_SET);
}

Dot11ManagementFrame::ibss_dfs_params Dot11ManagementFrame::ibss_dfs() const {
    return search_and_convert<ibss_dfs_params>(IBSS_DFS);
}

Dot11ManagementFrame::country_params Dot11ManagementFrame::country() const {
    return search_and_convert<country_params>(COUNTRY);
}

std::pair<uint8_t, uint8_t> Dot11ManagementFrame::fh_parameters() const {
    return search_and_convert<std::pair<uint8_t, uint8_t> >(HOPPING_PATTERN_PARAMS);
}

Dot11ManagementFrame::fh_pattern_type Dot11ManagementFrame::fh_pattern_table() const {
    return search_and_convert<fh_pattern_type>(HOPPING_PATTERN_TABLE);
}

uint8_t Dot11ManagementFrame::power_constraint() const {
    return search_and_convert<uint8_t>(POWER_CONSTRAINT);
}

Dot11ManagementFrame::channel_switch_type Dot11ManagementFrame::channel_switch() const {
    return search_and_convert<channel_switch_type>(CHANNEL_SWITCH);
}

Dot11ManagementFrame::quiet_type Dot11ManagementFrame::quiet() const {
    return search_and_convert<quiet_type>(QUIET);
}

std::pair<uint8_t, uint8_t> Dot11ManagementFrame::tpc_report() const {
    return search_and_convert<std::pair<uint8_t, uint8_t> >(TPC_REPORT);
}

uint8_t Dot11ManagementFrame::erp_information() const {
    return search_and_convert<uint8_t>(ERP_INFORMATION);
}

Dot11ManagementFrame::bss_load_type Dot11ManagementFrame::bss_load() const {
    return search_and_convert<bss_load_type>(BSS_LOAD);
}

Dot11ManagementFrame::tim_type Dot11ManagementFrame::tim() const {
    return search_and_convert<tim_type>(TIM);
}

std::string Dot11ManagementFrame::challenge_text() const {
    return search_and_convert<std::string>(CHALLENGE_TEXT);
}

Dot11ManagementFrame::vendor_specific_type Dot11ManagementFrame::vendor_specific() const {
    const Dot11::option *option = search_option(VENDOR_SPECIFIC);
    if(!option || option->data_size() < 3)
        throw option_not_found();
    return vendor_specific_type::from_bytes(option->data_ptr(), option->data_size());
}

Dot11ManagementFrame::vendor_specific_type 
  Dot11ManagementFrame::vendor_specific_type::from_bytes(const uint8_t *buffer, uint32_t sz) 
{
    if(sz < 3)
        throw malformed_option();
    return vendor_specific_type(
        buffer, 
        byte_array(buffer + 3, buffer + sz)
    );
}

// Options

Dot11ManagementFrame::fh_params_set Dot11ManagementFrame::fh_params_set::from_option(const option &opt)
{
    if(opt.data_size() != 5)
        throw malformed_option();
    fh_params_set output;
    std::memcpy(&output.dwell_time, opt.data_ptr(), sizeof(uint16_t));
    output.hop_set = opt.data_ptr()[2];
    output.hop_pattern = opt.data_ptr()[3];
    output.hop_index = opt.data_ptr()[4];
    return output;
}

Dot11ManagementFrame::cf_params_set Dot11ManagementFrame::cf_params_set::from_option(const option &opt) 
{
    if(opt.data_size() != 6)
        throw malformed_option();
    cf_params_set output;
    output.cfp_count = *opt.data_ptr();
    output.cfp_period = opt.data_ptr()[1];
    std::memcpy(&output.cfp_max_duration, &opt.data_ptr()[2], sizeof(uint16_t));
    std::memcpy(&output.cfp_dur_remaining, &opt.data_ptr()[4], sizeof(uint16_t));
    return output;
}

Dot11ManagementFrame::ibss_dfs_params Dot11ManagementFrame::ibss_dfs_params::from_option(const option &opt)
{
    if(opt.data_size() < ibss_dfs_params::minimum_size)
        throw malformed_option();
    ibss_dfs_params output;
    const uint8_t *ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    output.dfs_owner = ptr;
    ptr += output.dfs_owner.size();
    output.recovery_interval = *(ptr++);
    while(ptr != end) {
        uint8_t first = *(ptr++);
        if(ptr == end)
            throw option_not_found();
        output.channel_map.push_back(std::make_pair(first, *(ptr++)));
    }
    return output;
}

Dot11ManagementFrame::country_params Dot11ManagementFrame::country_params::from_option(const option &opt)
{
    if(opt.data_size() < country_params::minimum_size)
        throw malformed_option();
    country_params output;
    const uint8_t *ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    std::copy(ptr, ptr + 3, std::back_inserter(output.country));
    ptr += output.country.size();
    while(end - ptr >= 3) {
        output.first_channel.push_back(*(ptr++));
        output.number_channels.push_back(*(ptr++));
        output.max_transmit_power.push_back(*(ptr++));
    }
    if(ptr != end)
        throw malformed_option();
    return output; 
}

Dot11ManagementFrame::fh_pattern_type Dot11ManagementFrame::fh_pattern_type::from_option(const option &opt)
{
    if(opt.data_size() < fh_pattern_type::minimum_size)
        throw malformed_option();
    fh_pattern_type output;
    const uint8_t *ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    
    output.flag = *(ptr++);
    output.number_of_sets = *(ptr++);
    output.modulus = *(ptr++);
    output.offset = *(ptr++);
    
    output.random_table.assign(ptr, end);
    return output;
}

Dot11ManagementFrame::channel_switch_type Dot11ManagementFrame::channel_switch_type::from_option(const option &opt)
{
    if(opt.data_size() != sizeof(uint8_t) * 3)
        throw malformed_option();
    const uint8_t *ptr = opt.data_ptr();
    channel_switch_type output;
    output.switch_mode = *(ptr++);
    output.new_channel = *(ptr++);
    output.switch_count = *(ptr++);
    return output;
}

Dot11ManagementFrame::quiet_type Dot11ManagementFrame::quiet_type::from_option(const option &opt)
{
    if(opt.data_size() != (sizeof(uint8_t) * 2 + sizeof(uint16_t) * 2))
        throw malformed_option();
    const uint8_t *ptr = opt.data_ptr();
    quiet_type output;
    
    output.quiet_count = *(ptr++);
    output.quiet_period = *(ptr++);
    const uint16_t *ptr_16 = (const uint16_t*)ptr;
    output.quiet_duration = Endian::le_to_host(*(ptr_16++));
    output.quiet_offset = Endian::le_to_host(*ptr_16);
    return output;
}

Dot11ManagementFrame::bss_load_type Dot11ManagementFrame::bss_load_type::from_option(const option &opt)
{
    if(opt.data_size() != sizeof(uint8_t) + 2 * sizeof(uint16_t))
        throw malformed_option();
    bss_load_type output;
    
    const uint8_t *ptr = opt.data_ptr();
    std::memcpy(&output.station_count, ptr, sizeof(uint16_t));
    output.channel_utilization = ptr[2];
    std::memcpy(&output.available_capacity, ptr + 3, sizeof(uint16_t));
    output.available_capacity = Endian::le_to_host(output.available_capacity);
    return output;
}

Dot11ManagementFrame::tim_type Dot11ManagementFrame::tim_type::from_option(const option &opt)
{
    if(opt.data_size() < 4 * sizeof(uint8_t))
        throw malformed_option();
    const uint8_t *ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    tim_type output;
    
    output.dtim_count = *(ptr++);
    output.dtim_period = *(ptr++);
    output.bitmap_control = *(ptr++);
    
    output.partial_virtual_bitmap.assign(ptr, end);
    return output;
}
} // namespace Tins

#endif // HAVE_DOT11
