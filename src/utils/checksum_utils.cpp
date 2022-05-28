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

#include <tins/utils/checksum_utils.h>
#include <cstring>
#include <tins/ip_address.h>
#include <tins/ipv6_address.h>
#include <tins/endianness.h>
#include <tins/memory_helpers.h>

using std::memcpy;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {
namespace Utils {

uint32_t do_checksum(const uint8_t* start, const uint8_t* end) {
    return Endian::host_to_be<uint32_t>(sum_range(start, end));
}

uint16_t sum_range(const uint8_t* start, const uint8_t* end) {
    uint32_t checksum(0);
    const uint8_t* last = end;
    uint16_t buffer = 0;
    uint16_t padding = 0;
    const uint8_t* ptr = start;

    if (((end - start) & 1) == 1) {
        last = end - 1;
        padding = Endian::host_to_le<uint16_t>(*(end - 1));
    }

    while (ptr < last) {
        memcpy(&buffer, ptr, sizeof(uint16_t));
        checksum += buffer;
        ptr += sizeof(uint16_t);
    }

    checksum += padding;
    while (checksum >> 16) {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    return checksum;  
}

template <size_t buffer_size, typename AddressType>
uint32_t generic_pseudoheader_checksum(const AddressType& source_ip, 
                                       const AddressType& dest_ip,
                                       uint16_t len,
                                       uint16_t flag) {
    uint8_t buffer[buffer_size];
    OutputMemoryStream stream(buffer, sizeof(buffer));
    stream.write(source_ip);
    stream.write(dest_ip);
    stream.write(Endian::host_to_be(flag));
    stream.write(Endian::host_to_be(len));

    InputMemoryStream input_stream(buffer, sizeof(buffer));
    uint32_t checksum = 0;
    while (input_stream) {
        checksum += input_stream.read<uint16_t>();
    }
    return checksum;
}

uint32_t pseudoheader_checksum(IPv4Address source_ip, 
                               IPv4Address dest_ip,
                               uint16_t len,
                               uint16_t flag) {
    return generic_pseudoheader_checksum<sizeof(uint32_t) * 3>(
        source_ip, dest_ip, len, flag
    );
}

uint32_t pseudoheader_checksum(IPv6Address source_ip,
                               IPv6Address dest_ip,
                               uint16_t len,
                               uint16_t flag) {
    return generic_pseudoheader_checksum<IPv6Address::address_size * 2 + sizeof(uint16_t) * 2>(
        source_ip, dest_ip, len, flag
    );
}

uint32_t crc32(const uint8_t* data, uint32_t data_size) {
    uint32_t i, crc = 0;
    static uint32_t crc_table[] = {
        0x4DBDF21C, 0x500AE278, 0x76D3D2D4, 0x6B64C2B0,
        0x3B61B38C, 0x26D6A3E8, 0x000F9344, 0x1DB88320,
        0xA005713C, 0xBDB26158, 0x9B6B51F4, 0x86DC4190,
        0xD6D930AC, 0xCB6E20C8, 0xEDB71064, 0xF0000000
    };

    for (i = 0; i < data_size; ++i) {
        crc = (crc >> 4) ^ crc_table[(crc ^ data[i]) & 0x0F];
        crc = (crc >> 4) ^ crc_table[(crc ^ (data[i] >> 4)) & 0x0F];
    }

    return crc;
}

} // namespace Utils
} // namespace Tins
