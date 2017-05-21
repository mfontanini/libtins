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

#include "utils/radiotap_parser.h"
#include "exceptions.h"

using std::vector;

namespace Tins {
namespace Utils {

struct FieldMetadata {
    uint32_t size;
    uint32_t alignment;
};

static const FieldMetadata RADIOTAP_METADATA[] = {
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
    { 4, 4 }, // CHANNEL_PLUS
    { 3, 1 }, // MCS
};

static const uint64_t BIT_LIMIT = sizeof(RADIOTAP_METADATA) / sizeof(FieldMetadata) + 1;

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
    uint32_t offset = ((buffer - buffer_start) % n);
    if (offset) {
        offset = n - offset;
        if (offset > size) {
            throw malformed_packet();
        }
        buffer += offset;
    }
}

RadioTapParser::RadioTapParser(const vector<uint8_t>& buffer)
: current_namespace_(RADIOTAP_NS), current_bit_(0), namespace_index_(0) {
    if (TINS_UNLIKELY(buffer.empty())) {
        throw malformed_packet();
    }
    start_ = &*buffer.begin();
    end_ = start_ + buffer.size();
    const size_t max_size = end_ - start_;
    if (TINS_UNLIKELY(max_size < sizeof(RadiotapHeader))) {
        throw malformed_packet();
    }
    const RadiotapHeader* radio = (const RadiotapHeader*)start_;
    end_ = start_ + Endian::le_to_host(radio->length);
    current_ptr_ = find_options_start();
    // Skip all fields and make this point to the first flags one
    advance_to_next_field(true /* start from bit zero */);
}

RadioTapParser::NamespaceType RadioTapParser::current_namespace() const {
    return current_namespace_;
}

RadioTap::PresentFlags RadioTapParser::current_field() const {
    return static_cast<RadioTap::PresentFlags>(1 << current_bit_);
}

RadioTapParser::option RadioTapParser::current_option() {
    const uint32_t size = RADIOTAP_METADATA[current_bit_].size;
    if (TINS_UNLIKELY(current_ptr_ + size > end_)) {
        throw malformed_packet();
    }
    return option(current_field(), size, current_ptr_);
}

bool RadioTapParser::advance_field() {
    // If we manage to advance the field, return true
    if (advance_to_next_field(false /* keep going from current */)) {
        return true;
    }
    // Otherwise, let's try advancing the namespace. If we fail, then we failed
    if (!advance_to_next_namespace()) {
        return false;
    }
    // Otherwise restart bit and try to find the first field in this namespace
    current_bit_ = 0;
    return advance_to_next_field(true /* start from 0*/);
}

const uint8_t* RadioTapParser::find_options_start() const {
    uint32_t total_sz = end_ - start_;
    if (TINS_UNLIKELY(total_sz < sizeof(RadiotapHeader))) {
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

bool RadioTapParser::advance_to_next_field(bool start_from_zero) {
    const RadioTapFlags* flags = get_flags_ptr();
    uint64_t bit;
    if (start_from_zero) {
        bit = 0;
    }
    else {
        // Skip the payload
        current_ptr_ += RADIOTAP_METADATA[current_bit_].size;
        bit = current_bit_ + 1;
    }
    while (!is_field_set(1 << bit, flags) && bit < BIT_LIMIT) {
        bit++; 
    }
    if (bit < BIT_LIMIT) {
        // Skip and align the buffer
        align_buffer(start_, current_ptr_, end_ - start_, RADIOTAP_METADATA[bit].alignment);
        current_bit_ = bit;
        return true;
    }
    return false;
}

bool RadioTapParser::advance_to_next_namespace() {
    const uint32_t initial_index = namespace_index_;
    while (get_flags_ptr()->ext == 1) {
        const RadioTapFlags* flags = get_flags_ptr();
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
    }
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
    return (const RadioTapFlags*)(start_ + sizeof(uint32_t) * (namespace_index_ + 1));
}

} // Utils
} // Tins
