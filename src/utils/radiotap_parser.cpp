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

#include <tins/utils/radiotap_parser.h>

#ifdef TINS_HAVE_DOT11

#include <iostream>
#include <tins/exceptions.h>

using std::vector;

namespace Tins {
namespace Utils {

const RadioTapParser::FieldMetadata RadioTapParser::RADIOTAP_METADATA[] = {
    { 8, 8 }, /// TSFT
    { 1, 1 }, // FLAGS
    { 1, 1 }, // RATE
    { 4, 2 }, // CHANNEL
    { 2, 2 }, // FHSS
    { 1, 1 }, // DBM_SIGNAL
    { 1, 1 }, // DBM_NOISE
    { 2, 2 }, // LOCK_QUALITY
    { 2, 2 }, // TX_ATTENUATION
    { 2, 2 }, // DB_TX_ATTENUATION
    { 1, 1 }, // DBM_TX_ATTENUATION
    { 1, 1 }, // ANTENNA
    { 1, 1 }, // DB_SIGNAL
    { 1, 1 }, // DB_NOISE
    { 2, 2 }, // RX_FLAGS
    { 2, 2 }, // TX_FLAGS
    { 1, 1 }, // RTS_RETRIES
    { 1, 1 }, // DATA_RETRIES
    { 8, 4 }, // CHANNEL_PLUS
    { 3, 1 }, // MCS
    { 8, 4 }, // A-MPDU status
    { 12, 2 } // VHT
};

const uint32_t RadioTapParser::MAX_RADIOTAP_FIELD = sizeof(RADIOTAP_METADATA) /
                                                    sizeof(FieldMetadata) + 1;

#if TINS_IS_LITTLE_ENDIAN
TINS_BEGIN_PACK
struct RadioTapFlags {
    uint32_t
        tsft:1,
        flags:1,
        rate:1,
        channel:1,
        fhss:1,
        dbm_signal:1,
        dbm_noise:1,
        lock_quality:1,

        tx_attenuation:1,
        db_tx_attenuation:1,
        dbm_tx_power:1,
        antenna:1,
        db_signal:1,
        db_noise:1,
        rx_flags:1,
        tx_flags:1,

        reserved1:1,
        data_retries:1,
        channel_plus:1,
        mcs:1,
        reserved2:4,

        reserved3:7,
        ext:1;
} TINS_END_PACK;
#else
TINS_BEGIN_PACK
struct RadioTapFlags {
    uint32_t
        lock_quality:1,
        dbm_noise:1,
        dbm_signal:1,
        fhss:1,
        channel:1,
        rate:1,
        flags:1,
        tsft:1,

        tx_flags:1,
        rx_flags:1,
        db_noise:1,
        db_signal:1,
        antenna:1,
        dbm_tx_power:1,
        db_tx_attenuation:1,
        tx_attenuation:1,

        reserved2:4,
        mcs:1,
        channel_plus:1,
        data_retries:1,
        reserved1:1,

        ext:1,
        reserved3:7;
} TINS_END_PACK;
#endif

void align_buffer(const uint8_t* buffer_start, const uint8_t*& buffer, uint32_t size, size_t n) {
    uint32_t offset = (buffer - buffer_start) & (n - 1);
    if (offset) {
        offset = n - offset;
        if (TINS_UNLIKELY(offset > size)) {
            throw malformed_packet();
        }
        buffer += offset;
    }
}

RadioTapParser::RadioTapParser(const vector<uint8_t>& buffer)
: current_bit_(MAX_RADIOTAP_FIELD), current_flags_(0), namespace_index_(0),
  current_namespace_(RADIOTAP_NS) {
    if (buffer.empty()) {
        start_ = 0;
        end_ = 0;
        current_ptr_ = start_;
        current_flags_ = 0;
    }
    else {
        start_ = &*buffer.begin();
        end_ = start_ + buffer.size();
        load_current_flags();
        current_bit_ = 0;
        current_ptr_ = find_options_start();
        // Skip all fields and make this point to the first flags one
        advance_to_first_field();
    }
}

RadioTapParser::NamespaceType RadioTapParser::current_namespace() const {
    return current_namespace_;
}

uint32_t RadioTapParser::current_namespace_index() const {
    return namespace_index_;
}

RadioTap::PresentFlags RadioTapParser::current_field() const {
    return static_cast<RadioTap::PresentFlags>(1 << current_bit_);
}

RadioTap::option RadioTapParser::current_option() {
    const uint32_t size = RADIOTAP_METADATA[current_bit_].size;
    if (TINS_UNLIKELY(current_ptr_ + size > end_)) {
        throw malformed_packet();
    }
    return RadioTap::option(current_field(), size, current_ptr_);
}

const uint8_t* RadioTapParser::current_option_ptr() const {
    return current_ptr_;
}

bool RadioTapParser::advance_field() {
    // If we have no buffer to parse, then we can't advance
    if (start_ == 0 || current_bit_ == MAX_RADIOTAP_FIELD) {
        return false;
    }
    // If we manage to advance the field, return true
    if (skip_current_field()) {
        return true;
    }
    // Try to find the next namespace, as we've exhausted the current one
    if (!advance_to_next_namespace()) {
        current_bit_ = MAX_RADIOTAP_FIELD;
        return false;
    }
    current_bit_ = 0;
    // Try to find the first field in this new namespace
    if (!advance_to_first_field()) {
        current_bit_ = MAX_RADIOTAP_FIELD;
        return false;
    }
    return true;
}

bool RadioTapParser::advance_namespace() {
    if (static_cast<size_t>(end_ - start_) < sizeof(uint32_t)) {
        return false;
    }
    return advance_to_next_namespace();
}

RadioTap::PresentFlags RadioTapParser::namespace_flags() const {
    uint32_t output;
    memcpy(&output, get_flags_ptr(), sizeof(output));
    return static_cast<RadioTap::PresentFlags>(Endian::le_to_host(output));
}

bool RadioTapParser::skip_to_field(RadioTap::PresentFlags flag) {
    while (has_fields() && current_field() != flag) {
        advance_field();
    }
    return has_fields();
}

bool RadioTapParser::has_fields() const {
    return current_bit_ != MAX_RADIOTAP_FIELD;
}

bool RadioTapParser::has_field(RadioTap::PresentFlags flag) const {
    const uint8_t* ptr = start_;
    while (ptr + sizeof(uint32_t) < end_) {
        const RadioTapFlags* flags = (const RadioTapFlags*)ptr;
        if (is_field_set(flag, flags)) {
            return true;
        }
        if (!flags->ext) {
            break;
        }
        // Jump to the next flags field
        ptr += sizeof(uint32_t);
    }
    return false;
}

const uint8_t* RadioTapParser::find_options_start() const {
    uint32_t total_sz = end_ - start_;
    if (TINS_UNLIKELY(total_sz < sizeof(RadioTapFlags))) {
        throw malformed_packet();
    }
    // Skip fields before the flags one
    const RadioTapFlags* flags = get_flags_ptr();
    while (flags->ext == 1) {
        if (TINS_UNLIKELY(total_sz < sizeof(RadioTapFlags))) {
            throw malformed_packet();
        }
        ++flags;
        total_sz -= sizeof(RadioTapFlags);
    }
    return reinterpret_cast<const uint8_t*>(flags) + sizeof(RadioTapFlags);
}

bool RadioTapParser::advance_to_first_field() {
    return advance_to_next_field();
}

bool RadioTapParser::advance_to_next_field() {
    while ((current_flags_ & 1) == 0 && current_bit_ < MAX_RADIOTAP_FIELD) {
        current_bit_++;
        current_flags_ >>= 1;
    }
    if (current_bit_ < MAX_RADIOTAP_FIELD) {
        const uint8_t* radiotap_start = start_ - sizeof(uint32_t);
        // Skip and align the buffer
        align_buffer(radiotap_start, current_ptr_, end_ - radiotap_start,
                     RADIOTAP_METADATA[current_bit_].alignment);
        return true;
    }
    return false;
}

bool RadioTapParser::skip_current_field() {
    // Skip the payload
    current_ptr_ += RADIOTAP_METADATA[current_bit_].size;
    current_flags_ >>= 1;
    current_bit_++;
    return advance_to_next_field();
}

bool RadioTapParser::advance_to_next_namespace() {
    const uint32_t initial_index = namespace_index_;
    const RadioTapFlags* flags = get_flags_ptr();
    while (flags->ext == 1) {
        if (is_field_set(29, flags)) {
            current_namespace_ = RADIOTAP_NS;
        }
        else if (is_field_set(30, flags)) {
            current_namespace_ = VENDOR_NS;
        }
        else {
            current_namespace_ = UNKNOWN_NS;
        }
        namespace_index_++;
        flags++;
    }
    load_current_flags();
    return initial_index != namespace_index_;
}

bool RadioTapParser::is_field_set(uint32_t bit, const RadioTapFlags* flags) const {
    TINS_BEGIN_PACK
    union FlagsUnion {
        RadioTapFlags* flags;
        uint32_t flags_32;
    } TINS_END_PACK;
    const FlagsUnion* flags_union = reinterpret_cast<const FlagsUnion*>(flags); 
    return (Endian::le_to_host(flags_union->flags_32) & bit) != 0;
}

const RadioTapFlags* RadioTapParser::get_flags_ptr() const {
    return (const RadioTapFlags*)(start_ + sizeof(uint32_t) * namespace_index_);
}

void RadioTapParser::load_current_flags() {
    memcpy(&current_flags_, get_flags_ptr(), sizeof(current_flags_));
    current_flags_ = Endian::le_to_host(current_flags_);
}

} // Utils
} // Tins

#endif // TINS_HAVE_DOT11
