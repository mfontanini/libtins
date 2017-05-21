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

#include <algorithm>
#include "pdu.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "hw_address.h"
#include "endianness.h"
#include "pdu_option.h"

using std::vector;
using std::pair;
using std::string;
using std::memcpy;
using std::distance;

namespace Tins {
namespace Internals {
namespace Converters {

template <typename T>
T convert_to_integral(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian) {
    if (data_size != sizeof(T)) {
        throw malformed_option();
    }
    T data = *(T*)ptr;
    if (endian == PDU::BE) {
        data = Endian::be_to_host(data);
    }
    else {
        data = Endian::le_to_host(data);
    }
    return data;
}

template<typename T>
vector<T> convert_vector(const uint8_t* u8_ptr, uint32_t data_size, PDU::endian_type endian) {
    if (data_size % sizeof(T) != 0) {
        throw malformed_option();
    }
    const T* ptr = (const T*)u8_ptr;
    const T* end = (const T*)(ptr + data_size / sizeof(T));

    vector<T> output(distance(ptr, end));
    typename vector<T>::iterator it = output.begin();
    while (ptr < end) {
        if (endian == PDU::BE) {
            *it++ = Endian::be_to_host(*ptr++);
        }
        else {
            *it++ = Endian::le_to_host(*ptr++);
        }
    }
    return output;
}

template<typename T, typename U>
typename enable_if<is_unsigned_integral<T>::value && is_unsigned_integral<U>::value,
                   vector<std::pair<T, U> > >::type
convert_vector(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian) {
    if (data_size % (sizeof(T) + sizeof(U)) != 0) {
        throw malformed_option();
    }
    const uint8_t* end = ptr + data_size;

    std::vector<std::pair<T, U> > output;
    while (ptr < end) {
        pair<T, U> data;
        data.first = *(const T*)ptr;
        ptr += sizeof(T);
        data.second = *(const U*)ptr;
        ptr += sizeof(U);
        if (endian == PDU::BE) {
            data.first = Endian::be_to_host(data.first);
            data.second = Endian::be_to_host(data.second);
        }
        else {
            data.first = Endian::le_to_host(data.first);
            data.second = Endian::le_to_host(data.second);
        }
        output.push_back(data);
    }
    return output;
}

template<typename T, typename U>
typename enable_if<is_unsigned_integral<T>::value && is_unsigned_integral<U>::value,
                   std::pair<T, U> >::type
convert_pair(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian) {
    if (data_size != sizeof(T) + sizeof(U)) {
        throw malformed_option();
    }
    pair<T, U> output;
    memcpy(&output.first, ptr, sizeof(T));
    memcpy(&output.second, ptr + sizeof(T), sizeof(U));
    if (endian == PDU::BE) {
        output.first = Endian::be_to_host(output.first);
        output.second = Endian::be_to_host(output.second);
    }
    else {
        output.first = Endian::le_to_host(output.first);
        output.second = Endian::le_to_host(output.second);
    }
    return output;
}

uint8_t convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type, type_to_type<uint8_t>) {
    if (data_size != 1) {
        throw malformed_option();
    }
    return *ptr;
}

int8_t convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type, type_to_type<int8_t>) {
    if (data_size != 1) {
        throw malformed_option();
    }
    return *ptr;
}

uint16_t convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                 type_to_type<uint16_t>) {
    return convert_to_integral<uint16_t>(ptr, data_size, endian);

}

uint32_t convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                 type_to_type<uint32_t>) {
    return convert_to_integral<uint32_t>(ptr, data_size, endian);
}

uint64_t convert(const uint8_t* ptr, uint32_t data_size,
                                      PDU::endian_type endian, type_to_type<uint64_t>) {
    return convert_to_integral<uint64_t>(ptr, data_size, endian);
}

HWAddress<6> convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type,
                     type_to_type<HWAddress<6> >) {
    if (data_size != 6) {
        throw malformed_option();
    }
    return HWAddress<6>(ptr);
}

IPv4Address convert(const uint8_t* u8_ptr, uint32_t data_size, PDU::endian_type endian,
                    type_to_type<IPv4Address>) {
    if (data_size != sizeof(uint32_t)) {
        throw malformed_option();
    }
    const uint32_t* ptr = (const uint32_t*)u8_ptr;
    if (endian == PDU::BE) {
        return IPv4Address(*ptr);
    }
    else {
        return IPv4Address(Endian::change_endian(*ptr));
    }
}

IPv6Address convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type,
                    type_to_type<IPv6Address>) {
    if (data_size != IPv6Address::address_size) {
        throw malformed_option();
    }
    return IPv6Address(ptr);
}

string convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type,
               type_to_type<string>) {
    return string(ptr, ptr + data_size);
}

vector<float> convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type,
                      type_to_type<vector<float> >) {
    vector<float> output;
    const uint8_t* end = ptr + data_size;
    while (ptr != end) {
        output.push_back(float(*(ptr++) & 0x7f) / 2);
    }
    return output;
}

vector<uint8_t> convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                        type_to_type<vector<uint8_t> >) {
    return convert_vector<uint8_t>(ptr, data_size, endian);
}

vector<uint16_t> convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                         type_to_type<vector<uint16_t> >) {
    return convert_vector<uint16_t>(ptr, data_size, endian);
}

vector<uint32_t> convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                         type_to_type<vector<uint32_t> >) {
    return convert_vector<uint32_t>(ptr, data_size, endian);
}

vector<IPv4Address> convert(const uint8_t* u8_ptr, uint32_t data_size, PDU::endian_type endian,
                            type_to_type<vector<IPv4Address> >) {
    if (data_size % 4 != 0) {
        throw malformed_option();
    }
    const uint32_t* ptr = (const uint32_t*)u8_ptr;
    const uint32_t* end = (const uint32_t*)(ptr + data_size / sizeof(uint32_t));

    vector<IPv4Address> output(distance(ptr, end));
    vector<IPv4Address>::iterator it = output.begin();
    while (ptr < end) {
        if (endian == PDU::BE) {
            *it++ = IPv4Address(*ptr++);
        }
        else {
            *it++ = IPv4Address(Endian::change_endian(*ptr++));
        }
    }
    return output;
}

vector<IPv6Address> convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type,
                            type_to_type<vector<IPv6Address> >) {
    if (data_size % IPv6Address::address_size != 0) {
        throw malformed_option();
    }
    const uint8_t* end = ptr + data_size;
    vector<IPv6Address> output;
    while (ptr < end) {
        output.push_back(IPv6Address(ptr));
        ptr += IPv6Address::address_size;
    }
    return output;
}

vector<pair<uint8_t, uint8_t> > convert(const uint8_t* ptr, uint32_t data_size,
                                       PDU::endian_type endian,
                                       type_to_type<vector<pair<uint8_t, uint8_t> > >) {
    return convert_vector<uint8_t, uint8_t>(ptr, data_size, endian);
}

pair<uint8_t, uint8_t> convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                               type_to_type<pair<uint8_t, uint8_t> >) {
    return convert_pair<uint8_t, uint8_t>(ptr, data_size, endian);
}

pair<uint16_t, uint32_t> convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                                 type_to_type<pair<uint16_t, uint32_t> >) {
    return convert_pair<uint16_t, uint32_t>(ptr, data_size, endian);
}

pair<uint32_t, uint32_t> convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                                 type_to_type<pair<uint32_t, uint32_t> >) {
    return convert_pair<uint32_t, uint32_t>(ptr, data_size, endian);
}

} // Converters
} // Internals
} // Tins
