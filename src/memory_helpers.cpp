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

#include "memory_helpers.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "hw_address.h"

using std::vector;

namespace Tins {
namespace Memory {

// InputMemoryStream

InputMemoryStream::InputMemoryStream(const uint8_t* buffer, size_t total_sz)
: buffer_(buffer), size_(total_sz) {
}

InputMemoryStream::InputMemoryStream(const vector<uint8_t>& data)
: buffer_(&data[0]), size_(data.size()) {
}

void InputMemoryStream::skip(size_t size) {
    if (TINS_UNLIKELY(size > size_)) {
        throw malformed_packet();
    }
    buffer_ += size;
    size_ -= size;
}

bool InputMemoryStream::can_read(size_t byte_count) const {
    return TINS_LIKELY(size_ >= byte_count);
}

void InputMemoryStream::read(vector<uint8_t>& value, size_t count) {
    if (!can_read(count)) {
        throw malformed_packet();
    }
    value.assign(pointer(), pointer() + count);
    skip(count);
}

void InputMemoryStream::read(HWAddress<6>& address) {
    if (!can_read(address.size())) {
        throw malformed_packet();
    }
    address = pointer();
    skip(address.size());
}

void InputMemoryStream::read(IPv4Address& address) {
    address = IPv4Address(read<uint32_t>());
}

void InputMemoryStream::read(IPv6Address& address) {
    if (!can_read(IPv6Address::address_size)) {
        throw malformed_packet();
    }
    address = pointer();
    skip(IPv6Address::address_size);
}

void InputMemoryStream::read(void* output_buffer, size_t output_buffer_size) {
    if (!can_read(output_buffer_size)) {
        throw malformed_packet();
    }
    read_data(buffer_, (uint8_t*)output_buffer, output_buffer_size);
    skip(output_buffer_size);
}

const uint8_t* InputMemoryStream::pointer() const {
    return buffer_;
}

size_t InputMemoryStream::size() const {
    return size_;
}

void InputMemoryStream::size(size_t new_size) {
    size_ = new_size;
}

InputMemoryStream::operator bool() const {
    return size_ > 0;
}

// OutputMemoryStream

OutputMemoryStream::OutputMemoryStream(uint8_t* buffer, size_t total_sz)
: buffer_(buffer), size_(total_sz) {
}

OutputMemoryStream::OutputMemoryStream(vector<uint8_t>& buffer)
: buffer_(&buffer[0]), size_(buffer.size()) {
}

void OutputMemoryStream::skip(size_t size) {
    if (TINS_UNLIKELY(size > size_)) {
        throw malformed_packet();
    }
    buffer_ += size;
    size_ -= size;
}

void OutputMemoryStream::write(const uint8_t* ptr, size_t length) {
    write(ptr, ptr + length);
}

void OutputMemoryStream::write(const HWAddress<6>& address) {
    write(address.begin(), address.end());
}

void OutputMemoryStream::write(const IPv4Address& address) {
    write(static_cast<uint32_t>(address));
}

void OutputMemoryStream::write(const IPv6Address& address) {
    write(address.begin(), address.end());
}

void OutputMemoryStream::fill(size_t size, uint8_t value) {
    if (TINS_UNLIKELY(size_ < size)) {
        throw serialization_error();
    }
    std::memset(buffer_, value, size);
    skip(size);
}

uint8_t* OutputMemoryStream::pointer() {
    return buffer_;
}

size_t OutputMemoryStream::size() const {
    return size_;
}

} // Memory
} // Tins
