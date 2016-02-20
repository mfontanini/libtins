/*
 * Copyright (c) 2016, Matias Fontanini
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
#ifdef TINS_HAVE_DOT11

#include <cstring>
#include "rsn_information.h"
#include "memory_helpers.h"

using std::string;
using std::copy;
using std::vector;
using std::back_inserter;
using std::runtime_error;
using std::pair;
using std::make_pair;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

// Dot11ManagementFrame

Dot11ManagementFrame::Dot11ManagementFrame(const uint8_t* buffer, uint32_t total_sz) 
: Dot11(buffer, total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.skip(sizeof(dot11_header));
    stream.read(ext_header_);
    if (from_ds() && to_ds()) {
        stream.read(addr4_);
    }
}

Dot11ManagementFrame::Dot11ManagementFrame(const address_type& dst_hw_addr, 
                                           const address_type& src_hw_addr) 
: Dot11(dst_hw_addr), ext_header_() {
    type(Dot11::MANAGEMENT);
    addr2(src_hw_addr);
}

uint32_t Dot11ManagementFrame::header_size() const {
    uint32_t sz = Dot11::header_size() + sizeof(ext_header_);
    if (from_ds() && to_ds()) {
        sz += 6;
    }
    return sz;
}

void Dot11ManagementFrame::addr2(const address_type& new_addr2) {
    new_addr2.copy(ext_header_.addr2);
}

void Dot11ManagementFrame::addr3(const address_type& new_addr3) {
    new_addr3.copy(ext_header_.addr3);
}

void Dot11ManagementFrame::frag_num(small_uint<4> new_frag_num) {
    #if TINS_IS_LITTLE_ENDIAN
    ext_header_.frag_seq = new_frag_num | (ext_header_.frag_seq & 0xfff0);
    #else
    ext_header_.frag_seq = (new_frag_num << 8) | (ext_header_.frag_seq & 0xf0ff);
    #endif
}

void Dot11ManagementFrame::seq_num(small_uint<12> new_seq_num) {
    #if TINS_IS_LITTLE_ENDIAN
    ext_header_.frag_seq = (new_seq_num << 4) | (ext_header_.frag_seq & 0xf);
    #else
    ext_header_.frag_seq = Endian::host_to_le<uint16_t>(new_seq_num << 4) | 
                           (ext_header_.frag_seq & 0xf00);
    #endif
}

void Dot11ManagementFrame::addr4(const address_type& new_addr4) {
    addr4_ = new_addr4;
}

void Dot11ManagementFrame::write_ext_header(OutputMemoryStream& stream) {
    stream.write(ext_header_);
    if (from_ds() && to_ds()) {
        stream.write(addr4_);
    }
}

void Dot11ManagementFrame::ssid(const string& new_ssid) {
    add_tagged_option(
        Dot11::SSID, 
        static_cast<uint8_t>(new_ssid.size()),
        (const uint8_t*)new_ssid.c_str()
    );
}

void Dot11ManagementFrame::rsn_information(const RSNInformation& info) {
    RSNInformation::serialization_type buffer = info.serialize();
    add_tagged_option(RSN, static_cast<uint8_t>(buffer.size()), &buffer[0]);
}

vector<uint8_t> Dot11ManagementFrame::serialize_rates(const rates_type& rates) {
    vector<uint8_t> buffer(rates.size());
    uint8_t* ptr = &buffer[0];
    for (rates_type::const_iterator it = rates.begin(); it != rates.end(); ++it) {
        uint8_t result = static_cast<uint8_t>(*it * 2);
        if (result == 2 || result == 4 || result == 11 || result == 22) {
            result |= 0x80;
        }
        *(ptr++) = result;
    }
    return buffer;
}

Dot11ManagementFrame::rates_type Dot11ManagementFrame::deserialize_rates(const option* opt) {
    rates_type output;
    const uint8_t* ptr = opt->data_ptr(), *end = ptr + opt->data_size();
    while (ptr != end) {
        output.push_back(float(*(ptr++) & 0x7f) / 2);
    }
    return output;
}

void Dot11ManagementFrame::supported_rates(const rates_type& new_rates) {
    vector<uint8_t> buffer = serialize_rates(new_rates);
    add_tagged_option(SUPPORTED_RATES, static_cast<uint8_t>(buffer.size()), &buffer[0]);
}

void Dot11ManagementFrame::extended_supported_rates(const rates_type& new_rates) {
    vector<uint8_t> buffer = serialize_rates(new_rates);
    add_tagged_option(EXT_SUPPORTED_RATES, static_cast<uint8_t>(buffer.size()), &buffer[0]);
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

void Dot11ManagementFrame::supported_channels(const channels_type& new_channels) {
    vector<uint8_t> buffer(new_channels.size() * 2);
    uint8_t* ptr = &buffer[0];
    for (channels_type::const_iterator it = new_channels.begin(); it != new_channels.end(); ++it) {
        *(ptr++) = it->first;
        *(ptr++) = it->second;
    }
    add_tagged_option(SUPPORTED_CHANNELS, static_cast<uint8_t>(buffer.size()), &buffer[0]);
}

void Dot11ManagementFrame::edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo) {
    uint8_t buffer[18];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write<uint8_t>(0);
    stream.write<uint8_t>(0);
    stream.write_le(ac_be);
    stream.write_le(ac_bk);
    stream.write_le(ac_vi);
    stream.write_le(ac_vo);
    add_tagged_option(EDCA, sizeof(buffer), buffer);
}

void Dot11ManagementFrame::request_information(const request_info_type elements) {
    add_tagged_option(REQUEST_INFORMATION, static_cast<uint8_t>(elements.size()), &elements[0]);
}

void Dot11ManagementFrame::fh_parameter_set(const fh_params_set& fh_params) {
    uint8_t buffer[5];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write_le(fh_params.dwell_time);
    stream.write(fh_params.hop_set);
    stream.write(fh_params.hop_pattern);
    stream.write(fh_params.hop_index);
    add_tagged_option(FH_SET, sizeof(buffer), buffer);
}

void Dot11ManagementFrame::ds_parameter_set(uint8_t current_channel) {
    add_tagged_option(DS_SET, 1, &current_channel);
}

void Dot11ManagementFrame::cf_parameter_set(const cf_params_set& params) {
    uint8_t buffer[6];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write(params.cfp_count);
    stream.write(params.cfp_period);
    stream.write_le(params.cfp_max_duration);
    stream.write_le(params.cfp_dur_remaining);
    add_tagged_option(CF_SET, sizeof(buffer), buffer);
}

void Dot11ManagementFrame::ibss_parameter_set(uint16_t atim_window) {
    atim_window = Endian::host_to_le(atim_window);
    add_tagged_option(IBSS_SET, 2, (uint8_t*)&atim_window);
}

void Dot11ManagementFrame::ibss_dfs(const ibss_dfs_params& params) {
    const size_t sz = address_type::address_size + sizeof(uint8_t) + 
                      sizeof(uint8_t) * 2 * params.channel_map.size();
    vector<uint8_t> buffer(sz);
    OutputMemoryStream stream(buffer);
    stream.write(params.dfs_owner);
    stream.write(params.recovery_interval);
    for (channels_type::const_iterator it = params.channel_map.begin(); it != params.channel_map.end(); ++it) {
        stream.write(it->first);
        stream.write(it->second);
    }

    add_tagged_option(IBSS_DFS, static_cast<uint8_t>(buffer.size()), &buffer[0]);
}

void Dot11ManagementFrame::country(const country_params& params) {
    if ((params.first_channel.size() != params.number_channels.size()) ||
        (params.number_channels.size() != params.max_transmit_power.size())) {
        throw runtime_error("The length of the lists are distinct");
    }
    if (params.country.size() != 3) {
        throw runtime_error("Invalid country identifier length");
    }
    size_t sz = sizeof(uint8_t) * 3 * params.first_channel.size() + params.country.size();
    // Use 1 byte padding at the end if the length is odd.
    if ((sz & 1) == 1) {
        sz++;
    }
    vector<uint8_t> buffer(sz);
    uint8_t* ptr = copy(params.country.begin(), params.country.end(), &buffer[0]);
    for (size_t i(0); i < params.first_channel.size(); ++i) {
        *(ptr++) = params.first_channel[i];
        *(ptr++) = params.number_channels[i];
        *(ptr++) = params.max_transmit_power[i];
    }
    add_tagged_option(COUNTRY, static_cast<uint8_t>(sz), &buffer[0]);
}

void Dot11ManagementFrame::fh_parameters(uint8_t prime_radix, uint8_t number_channels) {
    uint8_t buffer[2];
    buffer[0] = prime_radix;
    buffer[1] = number_channels;
    add_tagged_option(HOPPING_PATTERN_PARAMS, 2, buffer);
}

void Dot11ManagementFrame::fh_pattern_table(const fh_pattern_type& params) {
    vector<uint8_t> data(sizeof(uint8_t) * 4 + params.random_table.size());
    uint8_t* ptr = &data[0];
    *(ptr++) = params.flag;
    *(ptr++) = params.number_of_sets;
    *(ptr++) = params.modulus;
    *(ptr++) = params.offset;
    byte_array::const_iterator it(params.random_table.begin());
    for (; it != params.random_table.end(); ++it) {
        *(ptr++) = *it;
    }
    add_tagged_option(HOPPING_PATTERN_TABLE, static_cast<uint8_t>(data.size()), &data[0]);
}

void Dot11ManagementFrame::power_constraint(uint8_t local_power_constraint) {
    add_tagged_option(POWER_CONSTRAINT, 1, &local_power_constraint);
}

void Dot11ManagementFrame::channel_switch(const channel_switch_type& data) {
    uint8_t buffer[3];
    buffer[0] = data.switch_mode;
    buffer[1] = data.new_channel;
    buffer[2] = data.switch_count;
    add_tagged_option(CHANNEL_SWITCH, 3, buffer);

}

void Dot11ManagementFrame::quiet(const quiet_type& data) {
    uint8_t buffer[6];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write(data.quiet_count);
    stream.write(data.quiet_period);
    stream.write_le(data.quiet_duration);
    stream.write_le(data.quiet_offset);
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

void Dot11ManagementFrame::bss_load(const bss_load_type& data) {
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

void Dot11ManagementFrame::tim(const tim_type& data) {
    vector<uint8_t> buffer(sizeof(uint8_t) * 3 + data.partial_virtual_bitmap.size());
    OutputMemoryStream stream(buffer);

    stream.write(data.dtim_count);
    stream.write(data.dtim_period);
    stream.write(data.bitmap_control);
    stream.write(
        data.partial_virtual_bitmap.begin(), 
        data.partial_virtual_bitmap.end()
    );
    add_tagged_option(TIM, static_cast<uint8_t>(buffer.size()), &buffer[0]);
}

void Dot11ManagementFrame::challenge_text(const string& text) {
    add_tagged_option(
        CHALLENGE_TEXT, 
        static_cast<uint8_t>(text.size()),
        (const uint8_t*)text.c_str()
    );
}

void Dot11ManagementFrame::vendor_specific(const vendor_specific_type& data) {
    byte_array buffer(3 + data.data.size());
    copy(
        data.data.begin(),
        data.data.end(),
        data.oui.copy(buffer.begin())
    );
    add_tagged_option(VENDOR_SPECIFIC, static_cast<uint8_t>(buffer.size()), &buffer[0]);
}

// Getters

RSNInformation Dot11ManagementFrame::rsn_information() const {
    return search_and_convert<RSNInformation>(RSN);
}

string Dot11ManagementFrame::ssid() const {
    const Dot11::option* option = search_option(SSID);
    if (!option) {
        throw option_not_found();
    }
    return option->to<string>();
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

pair<uint8_t, uint8_t> Dot11ManagementFrame::power_capability() const {
    return search_and_convert<pair<uint8_t, uint8_t> >(POWER_CAPABILITY);
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

pair<uint8_t, uint8_t> Dot11ManagementFrame::fh_parameters() const {
    return search_and_convert<pair<uint8_t, uint8_t> >(HOPPING_PATTERN_PARAMS);
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

pair<uint8_t, uint8_t> Dot11ManagementFrame::tpc_report() const {
    return search_and_convert<pair<uint8_t, uint8_t> >(TPC_REPORT);
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

string Dot11ManagementFrame::challenge_text() const {
    return search_and_convert<string>(CHALLENGE_TEXT);
}

Dot11ManagementFrame::vendor_specific_type Dot11ManagementFrame::vendor_specific() const {
    const Dot11::option* option = search_option(VENDOR_SPECIFIC);
    if (!option || option->data_size() < 3) {
        throw option_not_found();
    }
    return vendor_specific_type::from_bytes(
        option->data_ptr(), 
        static_cast<uint32_t>(option->data_size())
    );
}

Dot11ManagementFrame::vendor_specific_type 
Dot11ManagementFrame::vendor_specific_type::from_bytes(const uint8_t* buffer, uint32_t sz) {
    if (sz < 3) {
        throw malformed_option();
    }
    return vendor_specific_type(
        buffer, 
        byte_array(buffer + 3, buffer + sz)
    );
}

// Options

Dot11ManagementFrame::fh_params_set
Dot11ManagementFrame::fh_params_set::from_option(const option& opt) {
    if (opt.data_size() != 5) {
        throw malformed_option();
    }
    fh_params_set output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.dwell_time = stream.read_le<uint16_t>();
    output.hop_set = stream.read<uint8_t>();
    output.hop_pattern = stream.read<uint8_t>();
    output.hop_index = stream.read<uint8_t>();
    return output;
}

Dot11ManagementFrame::cf_params_set
Dot11ManagementFrame::cf_params_set::from_option(const option& opt) {
    if (opt.data_size() != 6) {
        throw malformed_option();
    }
    cf_params_set output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.cfp_count = stream.read<uint8_t>();
    output.cfp_period = stream.read<uint8_t>();
    output.cfp_max_duration = stream.read_le<uint16_t>();
    output.cfp_dur_remaining = stream.read_le<uint16_t>();
    return output;
}

Dot11ManagementFrame::ibss_dfs_params
Dot11ManagementFrame::ibss_dfs_params::from_option(const option& opt) {
    if (opt.data_size() < ibss_dfs_params::minimum_size) {
        throw malformed_option();
    }
    ibss_dfs_params output;
    const uint8_t* ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    output.dfs_owner = ptr;
    ptr += output.dfs_owner.size();
    output.recovery_interval = *(ptr++);
    while (ptr != end) {
        uint8_t first = *(ptr++);
        if (ptr == end) {
            throw malformed_option();
        }
        output.channel_map.push_back(make_pair(first, *(ptr++)));
    }
    return output;
}

Dot11ManagementFrame::country_params
Dot11ManagementFrame::country_params::from_option(const option& opt) {
    if (opt.data_size() < country_params::minimum_size) {
        throw malformed_option();
    }
    country_params output;
    const uint8_t* ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    copy(ptr, ptr + 3, back_inserter(output.country));
    ptr += output.country.size();
    while (end - ptr >= 3) {
        output.first_channel.push_back(*(ptr++));
        output.number_channels.push_back(*(ptr++));
        output.max_transmit_power.push_back(*(ptr++));
    }
    if (ptr != end) {
        throw malformed_option();
    }
    return output; 
}

Dot11ManagementFrame::fh_pattern_type
Dot11ManagementFrame::fh_pattern_type::from_option(const option& opt) {
    if (opt.data_size() < fh_pattern_type::minimum_size) {
        throw malformed_option();
    }
    fh_pattern_type output;
    const uint8_t* ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    
    output.flag = *(ptr++);
    output.number_of_sets = *(ptr++);
    output.modulus = *(ptr++);
    output.offset = *(ptr++);
    
    output.random_table.assign(ptr, end);
    return output;
}

Dot11ManagementFrame::channel_switch_type 
    Dot11ManagementFrame::channel_switch_type::from_option(const option& opt) {
    if (opt.data_size() != sizeof(uint8_t) * 3) {
        throw malformed_option();
    }
    const uint8_t* ptr = opt.data_ptr();
    channel_switch_type output;
    output.switch_mode = *(ptr++);
    output.new_channel = *(ptr++);
    output.switch_count = *(ptr++);
    return output;
}

Dot11ManagementFrame::quiet_type
Dot11ManagementFrame::quiet_type::from_option(const option& opt) {
    if (opt.data_size() != (sizeof(uint8_t) * 2 + sizeof(uint16_t) * 2)) {
        throw malformed_option();
    }
    quiet_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    
    output.quiet_count = stream.read<uint8_t>();
    output.quiet_period = stream.read<uint8_t>();
    output.quiet_duration = stream.read_le<uint16_t>();
    output.quiet_offset = stream.read_le<uint16_t>();
    return output;
}

Dot11ManagementFrame::bss_load_type 
Dot11ManagementFrame::bss_load_type::from_option(const option& opt) {
    if (opt.data_size() != sizeof(uint8_t) + 2 * sizeof(uint16_t)) {
        throw malformed_option();
    }
    bss_load_type output;
    InputMemoryStream stream(opt.data_ptr(), opt.data_size());
    output.station_count = stream.read_le<uint16_t>();
    output.channel_utilization = stream.read<uint8_t>();
    output.available_capacity = stream.read_le<uint16_t>();
    return output;
}

Dot11ManagementFrame::tim_type Dot11ManagementFrame::tim_type::from_option(const option& opt) {
    if (opt.data_size() < 4 * sizeof(uint8_t)) {
        throw malformed_option();
    }
    const uint8_t* ptr = opt.data_ptr(), *end = ptr + opt.data_size();
    tim_type output;
    
    output.dtim_count = *(ptr++);
    output.dtim_period = *(ptr++);
    output.bitmap_control = *(ptr++);
    
    output.partial_virtual_bitmap.assign(ptr, end);
    return output;
}

} // Tins

#endif // TINS_HAVE_DOT11
