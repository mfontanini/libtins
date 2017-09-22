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

#ifndef TINS_MEMORY_HELPERS_H
#define TINS_MEMORY_HELPERS_H

#include <stdint.h>
#include <cstring>
#include <vector>
#include <tins/exceptions.h>
#include <tins/endianness.h>

namespace Tins {

class IPv4Address;
class IPv6Address;
template <size_t n>
class HWAddress;

/** 
 * \cond
 */
namespace Memory {

inline void read_data(const uint8_t* buffer, uint8_t* output_buffer, size_t size) {
    std::memcpy(output_buffer, buffer, size);
}

template <typename T>
void read_value(const uint8_t* buffer, T& value) {
    std::memcpy(&value, buffer, sizeof(value));
}

inline void write_data(uint8_t* buffer, const uint8_t* ptr, size_t size) {
    std::memcpy(buffer, ptr, size);
}

template <typename T>
void write_value(uint8_t* buffer, const T& value) {
    std::memcpy(buffer, &value, sizeof(value));
}

class InputMemoryStream {
public:
    InputMemoryStream(const uint8_t* buffer, size_t total_sz)
    : buffer_(buffer), size_(total_sz) {
    }

    InputMemoryStream(const std::vector<uint8_t>& data) : buffer_(&data[0]), size_(data.size()) {
    }
 
    template <typename T>
    T read() {
        T output;
        read(output);
        return output;
    }

    template <typename T>
    T read_le() {
        return Endian::le_to_host(read<T>());
    }

    template <typename T>
    T read_be() {
        return Endian::be_to_host(read<T>());
    }

    template <typename T>
    void read(T& value) {
        if (!can_read(sizeof(value))) {
            throw malformed_packet();
        }
        read_value(buffer_, value);
        skip(sizeof(value));
    }

    void skip(size_t size) {
        if (TINS_UNLIKELY(size > size_)) {
            throw malformed_packet();
        }
        buffer_ += size;
        size_ -= size;
    }

    bool can_read(size_t byte_count) const {
        return TINS_LIKELY(size_ >= byte_count);
    }

    void read(void* output_buffer, size_t output_buffer_size) {
        if (!can_read(output_buffer_size)) {
            throw malformed_packet();
        }
        read_data(buffer_, (uint8_t*)output_buffer, output_buffer_size);
        skip(output_buffer_size);
    }

    const uint8_t* pointer() const {
        return buffer_;
    }

    size_t size() const {
        return size_;
    }

    void size(size_t new_size) {
        size_ = new_size;
    }

    operator bool() const {
        return size_ > 0;
    }

    void read(std::vector<uint8_t>& value, size_t count);
    void read(HWAddress<6>& address);
    void read(IPv4Address& address);
    void read(IPv6Address& address);
private:
    const uint8_t* buffer_;
    size_t size_;
};

class OutputMemoryStream {
public:
    OutputMemoryStream(uint8_t* buffer, size_t total_sz)
    : buffer_(buffer), size_(total_sz) {
    }

    OutputMemoryStream(std::vector<uint8_t>& buffer)
    : buffer_(&buffer[0]), size_(buffer.size()) {
    }

    template <typename T>
    void write(const T& value) {
        if (TINS_UNLIKELY(size_ < sizeof(value))) {
            throw serialization_error();
        }
        write_value(buffer_, value);
        skip(sizeof(value));
    }

    template <typename T>
    void write_be(const T& value) {
        write(Endian::host_to_be(value));
    }

    template <typename T>
    void write_le(const T& value) {
        write(Endian::host_to_le(value));
    }

    template <typename ForwardIterator>
    void write(ForwardIterator start, ForwardIterator end) {
        const size_t length = std::distance(start, end); 
        if (TINS_UNLIKELY(size_ < length)) {
            throw serialization_error();
        }
        // VC doesn't like dereferencing empty vector's iterators so check this here
        if (TINS_UNLIKELY(length == 0)) {
            return;
        }
        std::memcpy(buffer_, &*start, length);
        skip(length);
    }

    void skip(size_t size) {
        if (TINS_UNLIKELY(size > size_)) {
            throw malformed_packet();
        }
        buffer_ += size;
        size_ -= size;
    }

    void write(const uint8_t* ptr, size_t length) {
        write(ptr, ptr + length);
    }

    void fill(size_t size, uint8_t value) {
        if (TINS_UNLIKELY(size_ < size)) {
            throw serialization_error();
        }
        std::memset(buffer_, value, size);
        skip(size);
    }

    uint8_t* pointer() {
        return buffer_;
    }

    size_t size() const {
        return size_;
    }

    void write(const HWAddress<6>& address);
    void write(const IPv4Address& address);
    void write(const IPv6Address& address);
private:
    uint8_t* buffer_;
    size_t size_;
};

/** 
 * \endcond
 */

} // Memory
} // Tins

#endif // TINS_MEMORY_HELPERS_H
