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

#include "ip_address.h"
#include "ipv6_address.h"
#include "endianness.h"
#include "detail/address_helpers.h"

using Tins::IPv4Address;
using Tins::IPv6Address;

namespace Tins {
namespace Internals {

bool increment(IPv4Address &addr) {
    uint32_t addr_int = Endian::be_to_host<uint32_t>(addr);
    bool reached_end = ++addr_int == 0xffffffff;
    addr = IPv4Address(Endian::be_to_host<uint32_t>(addr_int));
    return reached_end;
}

bool increment(IPv6Address& addr) {
    return increment_buffer(addr);
}

bool decrement(IPv4Address& addr) {
    uint32_t addr_int = Endian::be_to_host<uint32_t>(addr);
    bool reached_end = --addr_int == 0;
    addr = IPv4Address(Endian::be_to_host<uint32_t>(addr_int));
    return reached_end;
}

bool decrement(IPv6Address& addr) {
    return decrement_buffer(addr);
}

IPv4Address last_address_from_mask(IPv4Address addr, IPv4Address mask) {
    uint32_t addr_int = Endian::be_to_host<uint32_t>(addr),
             mask_int = Endian::be_to_host<uint32_t>(mask);
    return IPv4Address(Endian::host_to_be(addr_int | ~mask_int));
}

IPv6Address last_address_from_mask(IPv6Address addr, const IPv6Address& mask) {
    IPv6Address::iterator addr_iter = addr.begin();
    for (IPv6Address::const_iterator it = mask.begin(); it != mask.end(); ++it, ++addr_iter) {
        *addr_iter = *addr_iter | ~*it;
    }
    return addr;
}

} // Internals
} // Tins
