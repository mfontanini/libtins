/*
 * Copyright (c) 2017, Matias Fontanini
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

#include <tins/radiotap.h>

#ifdef TINS_HAVE_DOT11

#include <cstring>
#include <tins/macros.h>
#ifndef _WIN32
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <net/if_dl.h>
    #else
        #include <netpacket/packet.h>
        #include <sys/socket.h>
    #endif
    #include <net/ethernet.h>
#endif
#include <tins/dot11/dot11_base.h>
#include <tins/packet_sender.h>
#include <tins/exceptions.h>
#include <tins/memory_helpers.h>
#include <tins/utils/checksum_utils.h>
#include <tins/utils/frequency_utils.h>
#include <tins/utils/radiotap_parser.h>
#include <tins/utils/radiotap_writer.h>

using std::memcpy;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

using Tins::Utils::RadioTapParser;
using Tins::Utils::RadioTapWriter;

namespace Tins {

template <typename T>
void add_integral_option(RadioTap& radio, RadioTap::PresentFlags type, T value) {
    uint8_t buffer[sizeof(value)];
    value = Endian::host_to_le(value);
    std::memcpy(buffer, &value, sizeof(value));
    radio.add_option(RadioTap::option(type, sizeof(buffer), buffer));
}

RadioTap::RadioTap()
: header_(), options_payload_(4) {
    channel(Utils::channel_to_mhz(1), 0xa0);
    flags(FCS);
    tsft(0);
    dbm_signal(-50);
    rx_flags(0);
    antenna(0);
}

RadioTap::RadioTap(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream input(buffer, total_sz);
    input.read(header_);
    uint32_t radiotap_size = length();
    if (TINS_UNLIKELY(radiotap_size < sizeof(header_) + sizeof(uint32_t))) {
        throw malformed_packet();
    }

    radiotap_size -= sizeof(header_);
    if (TINS_UNLIKELY(radiotap_size + sizeof(uint32_t) > input.size())) {
        throw malformed_packet();
    }

    options_payload_.assign(input.pointer(), input.pointer() + radiotap_size);
    input.skip(radiotap_size);

    total_sz = input.size();
    RadioTapParser parser(options_payload_);
    if (parser.skip_to_field(FLAGS)) {
        const uint8_t flags_value = *parser.current_option_ptr();
        if ((flags_value & FCS) != 0) {
            if (TINS_UNLIKELY(total_sz < sizeof(uint32_t))) {
                throw malformed_packet();
            }
            total_sz -= sizeof(uint32_t);
            if (TINS_UNLIKELY((flags_value & FAILED_FCS) != 0)) {
                throw malformed_packet();
            }
        }
    }

    if (TINS_LIKELY(total_sz)) {
        inner_pdu(Dot11::from_bytes(input.pointer(), total_sz));
    }
}

// Setter for RadioTap fields
void RadioTap::version(uint8_t new_version) {
    header_.it_version = new_version;
}

void RadioTap::padding(uint8_t new_padding) {
    header_.it_pad = new_padding;
}

void RadioTap::length(uint16_t new_length) {
    header_.it_len = Endian::host_to_le(new_length);
}

void RadioTap::tsft(uint64_t new_tsft) {
    add_integral_option(*this, TSFT, new_tsft);
}

void RadioTap::flags(FrameFlags new_flags) {
    add_integral_option(*this, FLAGS, static_cast<uint8_t>(new_flags));
}

void RadioTap::rate(uint8_t new_rate) {
    add_integral_option(*this, RATE, new_rate);
}

void RadioTap::channel(uint16_t new_freq, uint16_t new_type) {
    uint8_t buffer[sizeof(uint16_t) * 2];
    new_freq = Endian::host_to_le(new_freq);
    new_type = Endian::host_to_le(new_type);
    memcpy(buffer, &new_freq, sizeof(new_freq));
    memcpy(buffer + sizeof(new_freq), &new_type, sizeof(new_type));
    add_option(RadioTap::option(CHANNEL, sizeof(buffer), buffer));
}
void RadioTap::dbm_signal(int8_t new_dbm_signal) {
    add_integral_option(*this, DBM_SIGNAL, new_dbm_signal);
}

void RadioTap::dbm_noise(int8_t new_dbm_noise) {
    add_integral_option(*this, DBM_NOISE, new_dbm_noise);
}

void RadioTap::signal_quality(uint8_t new_signal_quality) {
    add_integral_option(*this, LOCK_QUALITY, new_signal_quality);
}

void RadioTap::data_retries(uint8_t new_data_retries) {
    add_integral_option(*this, DATA_RETRIES, new_data_retries);
}

void RadioTap::antenna(uint8_t new_antenna) {
    add_integral_option(*this, ANTENNA, new_antenna);
}

void RadioTap::db_signal(uint8_t new_db_signal) {
    add_integral_option(*this, DB_SIGNAL, new_db_signal);
}

void RadioTap::rx_flags(uint16_t new_rx_flags) {
    add_integral_option(*this, RX_FLAGS, new_rx_flags);
}

void RadioTap::tx_flags(uint16_t new_tx_flags) {
    add_integral_option(*this, TX_FLAGS, new_tx_flags);
}

void RadioTap::xchannel(xchannel_type new_xchannel) {
    uint8_t buffer[sizeof(new_xchannel)];
    new_xchannel.flags = Endian::host_to_le(new_xchannel.flags);
    new_xchannel.frequency = Endian::host_to_le(new_xchannel.frequency);
    memcpy(buffer, &new_xchannel, sizeof(new_xchannel));
    add_option(RadioTap::option(XCHANNEL, sizeof(buffer), buffer));
}

void RadioTap::mcs(const mcs_type& new_mcs) {
    uint8_t buffer[sizeof(new_mcs)];
    memcpy(buffer, &new_mcs, sizeof(new_mcs));
    add_option(RadioTap::option(MCS, sizeof(buffer), buffer));
}

RadioTap::PresentFlags RadioTap::present() const {
    uint32_t output = 0;
    RadioTapParser parser(options_payload_);
    do {
        output |= parser.namespace_flags();
    }
    while (parser.advance_namespace());
    return static_cast<PresentFlags>(output);
}

uint32_t RadioTap::header_size() const {
    return sizeof(header_) + options_payload_.size();
}

uint32_t RadioTap::trailer_size() const {
    RadioTapParser parser(options_payload_);
    if (parser.skip_to_field(FLAGS)) {
        const uint8_t flags_value = parser.current_option().to<uint8_t>();
        // If there's FCS at the end, then return its size
        if ((flags_value & FCS) != 0) {
            return sizeof(uint32_t);
        }
    }
    return 0;
}

void RadioTap::add_option(const option& opt) {
    Utils::RadioTapWriter writer(options_payload_);
    writer.write_option(opt);
}

const RadioTap::options_payload_type& RadioTap::options_payload() const {
    return options_payload_;
}

// Getter for RadioTap fields
uint8_t RadioTap::version() const {
    return header_.it_version;
}

uint8_t RadioTap::padding() const {
    return header_.it_pad;
}

uint16_t RadioTap::length() const {
    return Endian::le_to_host(header_.it_len);
}

uint64_t RadioTap::tsft() const {
    return do_find_option(TSFT).to<uint64_t>();
}

RadioTap::FrameFlags RadioTap::flags() const {
    return static_cast<FrameFlags>(do_find_option(FLAGS).to<uint8_t>());
}

uint8_t RadioTap::rate() const {
    return do_find_option(RATE).to<uint8_t>();
}

uint16_t RadioTap::channel_freq() const {
    const option opt = do_find_option(CHANNEL);
    uint16_t output;
    memcpy(&output, opt.data_ptr(), sizeof(uint16_t));
    return Endian::le_to_host(output);
}

uint16_t RadioTap::channel_type() const {
    const option opt = do_find_option(CHANNEL);
    uint16_t output;
    memcpy(&output, opt.data_ptr() + sizeof(uint16_t), sizeof(uint16_t));
    return Endian::le_to_host(output);
}

int8_t RadioTap::dbm_signal() const {
    return do_find_option(DBM_SIGNAL).to<int8_t>();
}

int8_t RadioTap::dbm_noise() const {
    return do_find_option(DBM_NOISE).to<int8_t>();
}

uint16_t RadioTap::signal_quality() const {
    return do_find_option(DBM_SIGNAL).to<uint16_t>();
}

uint8_t RadioTap::antenna() const {
    return do_find_option(ANTENNA).to<uint8_t>();
}

RadioTap::mcs_type RadioTap::mcs() const {
    const option opt = do_find_option(MCS);
    mcs_type output;
    memcpy(&output, opt.data_ptr(), sizeof(output));
    return output;
}

uint8_t RadioTap::db_signal() const {
    return do_find_option(DB_SIGNAL).to<uint8_t>();
}

RadioTap::xchannel_type RadioTap::xchannel() const {
    const option opt = do_find_option(XCHANNEL);
    xchannel_type output;
    memcpy(&output, opt.data_ptr(), sizeof(output));
    output.flags = Endian::le_to_host(output.flags);
    output.frequency = Endian::le_to_host(output.frequency);
    return output;
}

uint16_t RadioTap::rx_flags() const {
    return do_find_option(RX_FLAGS).to<uint16_t>();
}

uint16_t RadioTap::tx_flags() const {
    return do_find_option(TX_FLAGS).to<uint16_t>();
}

uint8_t RadioTap::data_retries() const {
    return do_find_option(DATA_RETRIES).to<uint8_t>();
}

#ifndef _WIN32
void RadioTap::send(PacketSender& sender, const NetworkInterface& iface) {
    if (!iface) {
        throw invalid_interface();
    }

    #if !defined(BSD) && !defined(__FreeBSD_kernel__)
        sockaddr_ll addr;

        memset(&addr, 0, sizeof(sockaddr_ll));

        addr.sll_family = Endian::host_to_be<uint16_t>(PF_PACKET);
        addr.sll_protocol = Endian::host_to_be<uint16_t>(ETH_P_ALL);
        addr.sll_halen = 6;
        addr.sll_ifindex = iface.id();

        const Tins::Dot11* wlan = tins_cast<Tins::Dot11*>(inner_pdu());
        if (wlan) {
            Tins::Dot11::address_type dot11_addr(wlan->addr1());
            std::copy(dot11_addr.begin(), dot11_addr.end(), addr.sll_addr);
        }

        sender.send_l2(*this, reinterpret_cast<sockaddr*>(&addr), static_cast<uint32_t>(sizeof(addr)), iface);
    #else
        sender.send_l2(*this, 0, 0, iface);
    #endif
}
#endif

bool RadioTap::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (sizeof(header_) < total_sz) {
        return false;
    }
    const radiotap_header* radio_ptr = reinterpret_cast<const radiotap_header*>(ptr);
    if (radio_ptr->it_len <= total_sz) {
        ptr += radio_ptr->it_len;
        total_sz -= radio_ptr->it_len;
        return inner_pdu() ? inner_pdu()->matches_response(ptr, total_sz) : true;
    }
    return false;
}

void RadioTap::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);
    header_.it_len = Endian::host_to_le<uint16_t>(header_size());
    stream.write(header_);
    stream.write(options_payload_.begin(), options_payload_.end());

    // If we have a trailer size, then we have the FCS flag on
    if (trailer_size() > 0 && inner_pdu()) {
    	uint32_t crc32 = Endian::host_to_le(
            Utils::crc32(stream.pointer(), inner_pdu()->size())
        );
        stream.skip(inner_pdu()->size());
        stream.write(crc32);
    }
}

RadioTap::option RadioTap::do_find_option(PresentFlags type) const {
    RadioTapParser parser(options_payload_);
    if (!parser.skip_to_field(type)) {
        throw field_not_present();
    }
    return parser.current_option();
}

} // Tins

#endif // TINS_HAVE_DOT11
