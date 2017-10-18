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

#include <tins/utils/radiotap_writer.h>

#ifdef TINS_HAVE_DOT11

#include <cmath>
#include <tins/utils/radiotap_parser.h>
#include <tins/exceptions.h>

using std::vector;

namespace Tins {
namespace Utils {

uint32_t calculate_padding(uint32_t alignment, uint32_t offset) {
    return offset % alignment;
}

uint32_t get_bit(uint32_t value) {
    return log(value) / log(2);
}

RadioTapWriter::RadioTapWriter(vector<uint8_t>& buffer)
: buffer_(buffer) {
}

void RadioTapWriter::write_option(const RadioTap::option& option) {
    const uint32_t bit = get_bit(option.option());
    if (bit > RadioTapParser::MAX_RADIOTAP_FIELD) {
        throw malformed_option();
    }
    const bool is_empty = buffer_.empty();
    RadioTapParser parser(buffer_);
    const uint8_t* candidate_ptr = parser.current_option_ptr();
    // Loop while we find lower fields and we're still in the first namespace
    while (parser.has_fields()) {
        if (parser.current_field() > option.option()) {
            break;
        }
        else if (parser.current_field() == option.option()) {
            memcpy(const_cast<uint8_t*>(parser.current_option_ptr()),
                   option.data_ptr(), option.data_size());
            return;
        }
        else {
            const uint32_t bit = get_bit(parser.current_field());
            const RadioTapParser::FieldMetadata& meta = RadioTapParser::RADIOTAP_METADATA[bit];
            candidate_ptr = parser.current_option_ptr() + meta.size;
        }
        parser.advance_field();
    }
    size_t offset = is_empty ? 0 : candidate_ptr - &*buffer_.begin();
    const RadioTapParser::FieldMetadata& meta = RadioTapParser::RADIOTAP_METADATA[bit];

    vector<uint8_t> paddings = build_padding_vector(candidate_ptr, parser);

    // Calculate the offset based on the RadioTap header (add 4 bytes)
    const uint32_t padding = calculate_padding(meta.alignment, offset + sizeof(uint32_t));

    // Now actually insert our new field (padding first)
    buffer_.insert(buffer_.begin() + offset, padding, 0);
    buffer_.insert(buffer_.begin() + offset + padding, option.data_ptr(),
                   option.data_ptr() + option.data_size());

    update_paddings(paddings, offset + padding + option.data_size());

    // Finally, update the flags
    uint32_t flags = 0;
    if (is_empty) {
        buffer_.insert(buffer_.begin(), sizeof(flags), 0);
    }
    else {
        memcpy(&flags, &*buffer_.begin(), sizeof(flags));
    }
    flags |= Endian::host_to_le<uint32_t>(option.option());
    memcpy(&*buffer_.begin(), &flags, sizeof(flags));
}

// Builds a vector that will contain the padding required for every position.
// e.g. if a 2 byte field is found, then in those 2 indexes we'll have the values [2, 1].
// 2 to indicate that the first field requires 16 bit padding and the second one is fine
// with 1 byte padding as long as the first one is as well.
//
// Padding bytes are filled with the value 0 to indicate a special index that can be 
// compacted/removed if less/more padding is required
vector<uint8_t> RadioTapWriter::build_padding_vector(const uint8_t* last_ptr,
                                                     RadioTapParser& parser) {
    vector<uint8_t> paddings;
    while (parser.has_fields()) {
        const uint32_t flag = static_cast<uint32_t>(parser.current_field());
        const uint32_t bit = get_bit(flag);
        const RadioTapParser::FieldMetadata& meta = RadioTapParser::RADIOTAP_METADATA[bit];
        const uint8_t* current_ptr = parser.current_option_ptr();
        // These are just paddings
        paddings.insert(paddings.end(), current_ptr - last_ptr, 0);
        // Say this byte has to be padded to whatever the alignment is for this field
        paddings.push_back(meta.alignment);
        // The rest of the bytes for this field don't really need alignment
        for (size_t i = 0; i < meta.size - 1; ++i) {
            paddings.push_back(1);
        }
        last_ptr = current_ptr + meta.size;
        parser.advance_field();
    }
    return paddings;
}

// Iterates the padding vector and extends/compacts the paddings as needed
void RadioTapWriter::update_paddings(const vector<uint8_t>& paddings, uint32_t offset) {
    size_t i = 0;
    while (i != paddings.size()) {
        // Skip everything that doesn't need padding
        while (i != paddings.size() && paddings[i] == 1) {
            ++i;
        }
        const size_t start = i;
        // Find the next field
        while (i != paddings.size() && paddings[i] == 0) {
            ++i;
        }
        if (i == paddings.size()) {
            break;
        }
        offset += start;
        const uint8_t needed_padding = calculate_padding(paddings[i], offset + sizeof(uint32_t));
        const size_t existing_padding = i - start;
        // Remove padding if there's too much
        if (existing_padding > needed_padding) {
            buffer_.erase(buffer_.begin() + offset,
                          buffer_.begin() + offset + (existing_padding - needed_padding));
            offset -= existing_padding - needed_padding;
        }
        // Add padding if there's too little
        else if (existing_padding < needed_padding) {
            buffer_.insert(buffer_.begin() + offset, needed_padding - existing_padding, 0);
            offset += needed_padding - existing_padding;
        }
        offset += i - start;
        ++i;
    }
}

} // Utils
} // Tins

#endif // TINS_HAVE_DOT11
