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

#include <algorithm>
#include <cstring>
#include "icmp_extension.h"
#include "exceptions.h"
#include "utils.h"
#include "memory_helpers.h"
#include "mpls.h"

using std::runtime_error;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

const uint32_t ICMPExtension::BASE_HEADER_SIZE = sizeof(uint16_t) + sizeof(uint8_t) * 2;

// ICMPExtension class

ICMPExtension::ICMPExtension() 
: extension_class_(0), extension_type_(0) {

} 

ICMPExtension::ICMPExtension(uint8_t ext_class, uint8_t ext_type)
: extension_class_(ext_class), extension_type_(ext_type) {

}


ICMPExtension::ICMPExtension(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);

    uint16_t length = stream.read_be<uint16_t>();
    extension_class_ = stream.read<uint8_t>();
    extension_type_ = stream.read<uint8_t>();
    // Length is BASE_HEADER_SIZE + payload size, make sure it's valid
    if (length < BASE_HEADER_SIZE || length - BASE_HEADER_SIZE > stream.size()) {
        throw malformed_packet();
    }
    length -= BASE_HEADER_SIZE;
    stream.read(payload_, length);
}

void ICMPExtension::extension_class(uint8_t value) {
    extension_class_ = value;
}

void ICMPExtension::extension_type(uint8_t value) {
    extension_type_ = value;
}

void ICMPExtension::payload(const payload_type& value) {
    payload_ = value;
}

uint32_t ICMPExtension::size() const {
    return BASE_HEADER_SIZE + payload_.size();
}

void ICMPExtension::serialize(uint8_t* buffer, uint32_t buffer_size) const {
    OutputMemoryStream stream(buffer, buffer_size);
    stream.write_be<uint16_t>(size());
    stream.write(extension_class_);
    stream.write(extension_type_);
    stream.write(payload_.begin(), payload_.end());
}

ICMPExtension::serialization_type ICMPExtension::serialize() const {
    serialization_type output(size());
    serialize(&output[0], output.size());
    return output;
}

// ICMPExtensionsStructure class

const uint32_t ICMPExtensionsStructure::MINIMUM_ICMP_PAYLOAD = 128;
const uint32_t ICMPExtensionsStructure::BASE_HEADER_SIZE = sizeof(uint16_t) * 2;

ICMPExtensionsStructure::ICMPExtensionsStructure() 
: version_and_reserved_(0), checksum_(0) {
    version(2);
}

ICMPExtensionsStructure::ICMPExtensionsStructure(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);

    version_and_reserved_ = stream.read<uint16_t>();
    checksum_ = stream.read<uint16_t>();
    while (stream) {
        extensions_.push_back(ICMPExtension(stream.pointer(), stream.size()));
        uint16_t size = stream.read_be<uint16_t>();
        stream.skip(size - sizeof(uint16_t));
    }
}

void ICMPExtensionsStructure::reserved(small_uint<12> value) {
    uint16_t current_value = Endian::be_to_host(version_and_reserved_);
    current_value &= 0xf000;
    current_value |= value;
    version_and_reserved_ = Endian::host_to_be(current_value);
}

void ICMPExtensionsStructure::version(small_uint<4> value) {
    uint16_t current_value = Endian::be_to_host(version_and_reserved_);
    current_value &= 0xfff;
    current_value |= value << 12;
    version_and_reserved_ = Endian::host_to_be(current_value);   
}

bool ICMPExtensionsStructure::validate_extensions(const uint8_t* buffer, uint32_t total_sz) {
    if (total_sz < BASE_HEADER_SIZE) {
        return false;
    }
    uint16_t checksum = *(const uint16_t*)(buffer + sizeof(uint16_t));
    // The buffer is read only, so we can't set the initial checksum to 0. Therefore, 
    // we sum the first 2 bytes and then the payload
    uint32_t actual_checksum = *(const uint16_t*)buffer;
    buffer += BASE_HEADER_SIZE;
    total_sz -= BASE_HEADER_SIZE;
    // Now do the checksum over the payload
    actual_checksum += Utils::sum_range(buffer, buffer + total_sz);
    return checksum == static_cast<uint16_t>(~actual_checksum);
}

uint32_t ICMPExtensionsStructure::size() const {
    typedef extensions_type::const_iterator iterator;
    uint32_t output = BASE_HEADER_SIZE;
    for (iterator iter = extensions_.begin(); iter != extensions_.end(); ++iter) {
        output += iter->size();
    }
    return output;
}

void ICMPExtensionsStructure::add_extension(const ICMPExtension& extension) {
    extensions_.push_back(extension);
}

void ICMPExtensionsStructure::add_extension(MPLS& mpls) {
    ICMPExtension extension(1, 1);
    extension.payload(mpls.serialize());
    add_extension(extension);
}

void ICMPExtensionsStructure::serialize(uint8_t* buffer, uint32_t buffer_size) {
    OutputMemoryStream stream(buffer, buffer_size);
    uint8_t* original_ptr = buffer;
    stream.write(version_and_reserved_);
    // Make checksum 0, for now, we'll compute it at the end
    stream.write<uint16_t>(0);

    typedef extensions_type::const_iterator iterator;
    for (iterator iter = extensions_.begin(); iter != extensions_.end(); ++iter) {
        iter->serialize(stream.pointer(), stream.size());
        stream.skip(iter->size());
    }
    uint16_t checksum = ~Utils::sum_range(original_ptr, original_ptr + size());
    memcpy(original_ptr + sizeof(uint16_t), &checksum, sizeof(checksum));
    checksum_ = checksum;
}

ICMPExtensionsStructure::serialization_type ICMPExtensionsStructure::serialize() {
    serialization_type output(size());
    serialize(&output[0], output.size());
    return output;
}

} // Tins
