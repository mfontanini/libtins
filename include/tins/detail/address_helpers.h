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

#ifndef TINS_ADDRESS_HELPERS_H
#define TINS_ADDRESS_HELPERS_H

#include <tins/hw_address.h>

/**
 * \cond
 */
namespace Tins {

class IPv4Address;
class IPv6Address;

namespace Internals {

template<typename T>
bool increment_buffer(T& addr) {
    typename T::iterator it = addr.end() - 1;
    while (it >= addr.begin() && *it == 0xff) {
        *it = 0;
        --it;
    }
    // reached end
    if (it < addr.begin()) {
        return true;
    }
    (*it)++;
    return false;
}

template<typename T>
bool decrement_buffer(T& addr) {
    typename T::iterator it = addr.end() - 1;
    while (it >= addr.begin() && *it == 0) {
        *it = 0xff;
        --it;
    }
    // reached end
    if (it < addr.begin()) {
        return true;
    }
    (*it)--;
    return false;
}

bool increment(IPv4Address& addr);
bool increment(IPv6Address& addr);
bool decrement(IPv4Address& addr);
bool decrement(IPv6Address& addr);
template<size_t n>
bool increment(HWAddress<n>& addr) {
    return increment_buffer(addr);
}
template<size_t n>
bool decrement(HWAddress<n>& addr) {
    return decrement_buffer(addr);
}

IPv4Address last_address_from_mask(IPv4Address addr, IPv4Address mask);
IPv6Address last_address_from_mask(IPv6Address addr, const IPv6Address& mask);
template<size_t n>
HWAddress<n> last_address_from_mask(HWAddress<n> addr, const HWAddress<n>& mask) {
    typename HWAddress<n>::iterator addr_iter = addr.begin();
    for (typename HWAddress<n>::const_iterator it = mask.begin(); it != mask.end(); ++it, ++addr_iter) {
        *addr_iter = *addr_iter | ~*it;
    }
    return addr;
}

} // Internals
} // Tins

/**
 * \endcond
 */

#endif // TINS_ADDRESS_HELPERS_H
