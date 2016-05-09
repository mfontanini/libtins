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

#include "radiotap.h"

#ifdef TINS_HAVE_DOT11

#include <cstring>
#include <stdexcept>
#include "macros.h"
#ifndef _WIN32
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <net/if_dl.h>
    #else
        #include <netpacket/packet.h>
        #include <sys/socket.h>
    #endif
    #include <net/ethernet.h>
#endif
#include "dot11/dot11_base.h"
#include "utils.h"
#include "packet_sender.h"
#include "exceptions.h"
#include "memory_helpers.h"

using std::memcpy;

using Tins::Memory::OutputMemoryStream;

namespace Tins {

void check_size(uint32_t total_sz, size_t field_size) {
    if (total_sz < field_size) {
        throw malformed_packet();
    }
}

template<typename T>
void read_field(const uint8_t* &buffer, uint32_t& total_sz, T& field) {
    check_size(total_sz, sizeof(field));
    memcpy(&field, buffer, sizeof(field));
    buffer += sizeof(field);
    total_sz -= sizeof(field);
}

RadioTap::RadioTap() : radio_() {
    init();
}

RadioTap::RadioTap(const uint8_t* buffer, uint32_t total_sz) {
    check_size(total_sz, sizeof(radio_));
    const uint8_t* buffer_start = buffer;
    memcpy(&radio_, buffer, sizeof(radio_));
    uint32_t radiotap_hdr_size = length();
    check_size(total_sz, radiotap_hdr_size);
    // We start on the first flags field, skipping version, pad and length.
    const flags_type* current_flags = (const flags_type*)(buffer + sizeof(uint32_t));
    const uint32_t extra_flags_size = find_extra_flag_fields_size(
        buffer + sizeof(uint32_t), total_sz);
    // Find and skip the extra flag fields.
    buffer += extra_flags_size;
    radiotap_hdr_size -= extra_flags_size;
    // Also skip the header
    buffer += sizeof(radio_);
    radiotap_hdr_size -= sizeof(radio_);

    while (true) {
        radio_.flags_32 |= *(const uint32_t*)current_flags;
        if (current_flags->tsft) {
            align_buffer<8>(buffer_start, buffer, radiotap_hdr_size);
            read_field(buffer, radiotap_hdr_size, tsft_);
        }

        if (current_flags->flags) {
            read_field(buffer, radiotap_hdr_size, flags_);
        }

        if (current_flags->rate) {
            read_field(buffer, radiotap_hdr_size, rate_);
        }

        if (current_flags->channel) {
            align_buffer<2>(buffer_start, buffer, radiotap_hdr_size);
            read_field(buffer, radiotap_hdr_size, channel_freq_);
            read_field(buffer, radiotap_hdr_size, channel_type_);
        }

        if (current_flags->dbm_signal) {
            read_field(buffer, radiotap_hdr_size, dbm_signal_);
        }

        if (current_flags->dbm_noise) {
            read_field(buffer, radiotap_hdr_size, dbm_noise_);
        }

        if (current_flags->lock_quality) {
            read_field(buffer, radiotap_hdr_size, signal_quality_);
        }

        if (current_flags->antenna) {
            read_field(buffer, radiotap_hdr_size, antenna_);
        }

        if (current_flags->db_signal) {
            read_field(buffer, radiotap_hdr_size, db_signal_);
        }

        if (current_flags->rx_flags) {
            align_buffer<2>(buffer_start, buffer, radiotap_hdr_size);
            read_field(buffer, radiotap_hdr_size, rx_flags_);
        }

        if (current_flags->tx_flags) {
            align_buffer<2>(buffer_start, buffer, radiotap_hdr_size);
            read_field(buffer, radiotap_hdr_size, tx_flags_);
        }

        if (current_flags->data_retries) {
            read_field(buffer, radiotap_hdr_size, data_retries_);
        }

        if (current_flags->channel_plus) {
            align_buffer<4>(buffer_start, buffer, radiotap_hdr_size);
            uint32_t dummy;
            read_field(buffer, radiotap_hdr_size, dummy);
            // nasty Big Endian fix
            channel_type_ = Endian::le_to_host<uint16_t>(Endian::host_to_le<uint32_t>(dummy));
            read_field(buffer, radiotap_hdr_size, channel_freq_);
            read_field(buffer, radiotap_hdr_size, channel_);
            read_field(buffer, radiotap_hdr_size, max_power_);
        }
        if (current_flags->mcs) {
            read_field(buffer, radiotap_hdr_size, mcs_.known);
            read_field(buffer, radiotap_hdr_size, mcs_.flags);
            read_field(buffer, radiotap_hdr_size, mcs_.mcs);
        } 
        // We can do this safely because we checked the size on find_extra_flags...
        if (current_flags->ext == 1) {
            current_flags++;
        }
        else {
            break;
        }
    }

    total_sz -= length();
    buffer += radiotap_hdr_size;

    if (radio_.flags.flags && (flags() & FCS) != 0) {
        check_size(total_sz, sizeof(uint32_t));
        total_sz -= sizeof(uint32_t);
        if ((flags() & FAILED_FCS) !=0) {
            throw malformed_packet();
        }
    }

    if (total_sz) {
        inner_pdu(Dot11::from_bytes(buffer, total_sz));
    }
}

void RadioTap::init() {
    channel(Utils::channel_to_mhz(1), 0xa0);
    flags(FCS);
    tsft(0);
    dbm_signal(-50);
    rx_flags(0);
    antenna(0);
}

// This method finds the extra flags field size, taking into account other
// set of flags that may appear if the "ext" bit is on/.
uint32_t RadioTap::find_extra_flag_fields_size(const uint8_t* buffer, uint32_t total_sz) {
    const flags_type* ptr = (const flags_type*)buffer;
    while (ptr->ext == 1) {
        if (total_sz < sizeof(flags_type)) {
            throw malformed_packet();
        }
        ++ptr;
    }

    return static_cast<uint32_t>((const uint8_t*)ptr - buffer);
}

// Setter for RadioTap fields
void RadioTap::version(uint8_t new_version) {
    radio_.it_version = new_version;
}

void RadioTap::padding(uint8_t new_padding) {
    radio_.it_pad = new_padding;
}

void RadioTap::length(uint16_t new_length) {
    radio_.it_len = Endian::host_to_le(new_length);
}

void RadioTap::tsft(uint64_t new_tsft) {
    tsft_ = Endian::host_to_le(new_tsft);
    radio_.flags.tsft = 1;
}

void RadioTap::flags(FrameFlags new_flags) {
    flags_ = (uint8_t)new_flags;
    radio_.flags.flags = 1;
}

void RadioTap::rate(uint8_t new_rate) {
    rate_ = new_rate;
    radio_.flags.rate = 1;
}

void RadioTap::channel(uint16_t new_freq, uint16_t new_type) {
    channel_freq_ = Endian::host_to_le(new_freq);
    channel_type_ = Endian::host_to_le(new_type);
    radio_.flags.channel = 1;
}
void RadioTap::dbm_signal(int8_t new_dbm_signal) {
    dbm_signal_ = new_dbm_signal;
    radio_.flags.dbm_signal = 1;
}

void RadioTap::dbm_noise(int8_t new_dbm_noise) {
    dbm_noise_ = new_dbm_noise;
    radio_.flags.dbm_noise = 1;
}

void RadioTap::signal_quality(uint8_t new_signal_quality) {
    signal_quality_ = new_signal_quality;
    radio_.flags.lock_quality = 1;
}

void RadioTap::data_retries(uint8_t new_data_retries) {
    data_retries_ = new_data_retries;
    radio_.flags.data_retries = 1;
}

void RadioTap::antenna(uint8_t new_antenna) {
    antenna_ = new_antenna;
    radio_.flags.antenna = 1;
}

void RadioTap::db_signal(uint8_t new_db_signal) {
    db_signal_ = new_db_signal;
    radio_.flags.db_signal = 1;
}

void RadioTap::rx_flags(uint16_t new_rx_flag) {
    rx_flags_ = Endian::host_to_le(new_rx_flag);
    radio_.flags.rx_flags = 1;
}

void RadioTap::tx_flags(uint16_t new_tx_flag) {
    tx_flags_ = Endian::host_to_le(new_tx_flag);
    radio_.flags.tx_flags = 1;
}

void RadioTap::mcs(const mcs_type& new_mcs) {
    mcs_ = new_mcs;
    radio_.flags.mcs = 1;   
}

uint32_t RadioTap::header_size() const {
    uint32_t total_bytes = 0;
    if (radio_.flags.tsft) {
        total_bytes += sizeof(tsft_);
    }
    if (radio_.flags.flags) {
        total_bytes += sizeof(flags_);
    }
    if (radio_.flags.rate) {
        total_bytes += sizeof(rate_);
    }
    if (radio_.flags.channel) {
        total_bytes += (total_bytes & 1);
        total_bytes += sizeof(uint16_t) * 2;
    }
    if (radio_.flags.dbm_signal) {
        total_bytes += sizeof(dbm_signal_);
    }
    if (radio_.flags.dbm_noise) {
        total_bytes += sizeof(dbm_noise_);
    }
    if (radio_.flags.lock_quality) {
        total_bytes += (total_bytes & 1);
        total_bytes += sizeof(signal_quality_);
    }
    if (radio_.flags.antenna) {
        total_bytes += sizeof(antenna_);
    }
    if (radio_.flags.db_signal) {
        total_bytes += sizeof(db_signal_);
    }
    if (radio_.flags.rx_flags) {
        total_bytes += (total_bytes & 1);
        total_bytes += sizeof(rx_flags_);
    }
    if (radio_.flags.tx_flags) {
        total_bytes += (total_bytes & 1);
        total_bytes += sizeof(tx_flags_);
    }
    if (radio_.flags.data_retries) {
        total_bytes += sizeof(data_retries_);
    }
    if (radio_.flags.channel_plus) {
        uint32_t offset = total_bytes % 4;
        if (offset) {
            total_bytes += 4 - offset;
        }
        total_bytes += 8;
    }
    if (radio_.flags.mcs) {
        total_bytes += sizeof(mcs_);
    }

    return sizeof(radio_) + total_bytes;
}

uint32_t RadioTap::trailer_size() const {
    // will be sizeof(uint32_t) if the FCS-at-the-end bit is on.
    return ((flags_ & 0x10) != 0) ? sizeof(uint32_t) : 0;
}

// Getter for RadioTap fields
uint8_t RadioTap::version() const {
    return radio_.it_version;
}

uint8_t RadioTap::padding() const {
    return radio_.it_pad;
}

uint16_t RadioTap::length() const {
    return Endian::le_to_host(radio_.it_len);
}

uint64_t RadioTap::tsft() const {
   if (!radio_.flags.tsft) {
        throw field_not_present();
   }
    return Endian::le_to_host(tsft_);
}

RadioTap::FrameFlags RadioTap::flags() const {
    if (!radio_.flags.flags) {
        throw field_not_present();
    }
    return (FrameFlags)flags_;
}

uint8_t RadioTap::rate() const {
    if (!radio_.flags.rate) {
        throw field_not_present();
    }
    return rate_;
}

uint16_t RadioTap::channel_freq() const {
    if (!radio_.flags.channel) {
        throw field_not_present();
    }
    return Endian::le_to_host(channel_freq_);
}

uint16_t RadioTap::channel_type() const {
    if (!radio_.flags.channel) {
        throw field_not_present();
    }
    return Endian::le_to_host(channel_type_);
}

int8_t RadioTap::dbm_signal() const {
    if (!radio_.flags.dbm_signal) {
        throw field_not_present();
    }
    return dbm_signal_;
}

int8_t RadioTap::dbm_noise() const {
    if (!radio_.flags.dbm_noise) {
        throw field_not_present();
    }
    return dbm_noise_;
}

uint16_t RadioTap::signal_quality() const {
    if (!radio_.flags.lock_quality) {
        throw field_not_present();
    }
    return signal_quality_;
}

uint8_t RadioTap::antenna() const {
    if (!radio_.flags.antenna) {
        throw field_not_present();
    }
    return antenna_;
}

RadioTap::mcs_type RadioTap::mcs() const {
    if (!radio_.flags.mcs) {
        throw field_not_present();
    }
    return mcs_;
}

uint8_t RadioTap::db_signal() const {
    if (!radio_.flags.db_signal) {
        throw field_not_present();
    }
    return db_signal_;
}

uint32_t RadioTap::channel_plus() const {
    if (!radio_.flags.channel_plus) {
        throw field_not_present();
    }
    return Endian::le_to_host<uint32_t>(channel_type_);
}

uint16_t RadioTap::rx_flags() const {
    if (!radio_.flags.rx_flags) {
        throw field_not_present();
    }
    return Endian::le_to_host(rx_flags_);
}

uint16_t RadioTap::tx_flags() const {
    if (!radio_.flags.tx_flags) {
        throw field_not_present();
    }
    return Endian::le_to_host(tx_flags_);
}

uint8_t RadioTap::data_retries() const {
    if (!radio_.flags.data_retries) {
        throw field_not_present();
    }
    return data_retries_;
}

#ifndef _WIN32
void RadioTap::send(PacketSender& sender, const NetworkInterface& iface) {
    if (!iface) {
        throw invalid_interface();
    }

    #if !defined(BSD) && !defined(__FreeBSD_kernel__)
        struct sockaddr_ll addr;

        memset(&addr, 0, sizeof(struct sockaddr_ll));

        addr.sll_family = Endian::host_to_be<uint16_t>(PF_PACKET);
        addr.sll_protocol = Endian::host_to_be<uint16_t>(ETH_P_ALL);
        addr.sll_halen = 6;
        addr.sll_ifindex = iface.id();

        const Tins::Dot11* wlan = tins_cast<Tins::Dot11*>(inner_pdu());
        if (wlan) {
            Tins::Dot11::address_type dot11_addr(wlan->addr1());
            std::copy(dot11_addr.begin(), dot11_addr.end(), addr.sll_addr);
        }

        sender.send_l2(*this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr), iface);
    #else
        sender.send_l2(*this, 0, 0, iface);
    #endif
}
#endif

bool RadioTap::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (sizeof(radio_) < total_sz) {
        return false;
    }
    const radiotap_hdr* radio_ptr = (const radiotap_hdr*)ptr;
    if (radio_ptr->it_len <= total_sz) {
        ptr += radio_ptr->it_len;
        total_sz -= radio_ptr->it_len;
        return inner_pdu() ? inner_pdu()->matches_response(ptr, total_sz) : true;
    }
    return false;
}

void RadioTap::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent) {
    OutputMemoryStream stream(buffer, total_sz);
    uint8_t* buffer_start = buffer;
    radio_.it_len = Endian::host_to_le<uint16_t>(header_size());
    stream.write(radio_);
    if (radio_.flags.tsft) {
        stream.write(tsft_);
    }
    if (radio_.flags.flags) {
        stream.write(flags_);
    }
    if (radio_.flags.rate) {
        stream.write(rate_);
    }
    if (radio_.flags.channel) {
        if (((stream.pointer() - buffer_start) & 1) == 1) {
            stream.write<uint8_t>(0);
        }
        stream.write(channel_freq_);
        stream.write(channel_type_);
    }
    if (radio_.flags.dbm_signal) {
        stream.write(dbm_signal_);
    }
    if (radio_.flags.dbm_noise) {
        stream.write(dbm_noise_);
    }
    if (radio_.flags.lock_quality) {
        if (((stream.pointer() - buffer_start) & 1) == 1) {
            stream.write<uint8_t>(0);
        }
        stream.write(signal_quality_);
    }
    if (radio_.flags.antenna) {
        stream.write(antenna_);
    }
    if (radio_.flags.db_signal) {
        stream.write(db_signal_);
    }
    if (radio_.flags.rx_flags) {
        if (((stream.pointer() - buffer_start) & 1) == 1) {
            stream.write<uint8_t>(0);
        }
        stream.write(rx_flags_);
    }
    if (radio_.flags.channel_plus) {
        const uint32_t padding = ((stream.pointer() - buffer_start) % 4);
        if (padding != 0) {
            stream.fill(4 - padding, 0);
        }
        uint32_t dummy = channel_type_;
        // nasty Big Endian fix
        dummy = Endian::le_to_host<uint32_t>(Endian::host_to_le<uint16_t>(dummy));
        stream.write(dummy);
        stream.write(channel_freq_);
        stream.write(channel_);
        stream.write(max_power_);
    }
    if ((flags_ & 0x10) != 0 && inner_pdu()) {
    	uint32_t crc32 = Endian::host_to_le(
            Utils::crc32(stream.pointer(), inner_pdu()->size())
        );
        stream.skip(inner_pdu()->size());
        stream.write(crc32);
    }
}

} // Tins

#endif // TINS_HAVE_DOT11
