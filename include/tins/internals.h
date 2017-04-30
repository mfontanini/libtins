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

#ifndef TINS_INTERNALS_H
#define TINS_INTERNALS_H

#include <string>
#include <stdint.h>
#include "constants.h"
#include "pdu.h"
#include "hw_address.h"
#include "macros.h"
#include "detail/type_traits.h"

/**
 * \cond
 */
namespace Tins {
namespace Memory {

class InputMemoryStream;
} // Memory
class IPv4Address;
class IPv6Address;
class ICMPExtensionsStructure;

namespace Internals {

PDU* pdu_from_flag(Constants::Ethernet::e flag, const uint8_t* buffer,
  uint32_t size, bool rawpdu_on_no_match = true);
PDU* pdu_from_flag(Constants::IP::e flag, const uint8_t* buffer,
  uint32_t size, bool rawpdu_on_no_match = true);
#ifdef TINS_HAVE_PCAP
PDU* pdu_from_dlt_flag(int flag, const uint8_t* buffer,
  uint32_t size, bool rawpdu_on_no_match = true);
#endif // TINS_HAVE_PCAP
PDU* pdu_from_flag(PDU::PDUType type, const uint8_t* buffer, uint32_t size);

Constants::Ethernet::e pdu_flag_to_ether_type(PDU::PDUType flag);
PDU::PDUType ether_type_to_pdu_flag(Constants::Ethernet::e flag);
Constants::IP::e pdu_flag_to_ip_type(PDU::PDUType flag);
PDU::PDUType ip_type_to_pdu_flag(Constants::IP::e flag);

uint32_t get_padded_icmp_inner_pdu_size(const PDU* inner_pdu, uint32_t pad_alignment);
void try_parse_icmp_extensions(Memory::InputMemoryStream& stream,
    uint32_t payload_length, ICMPExtensionsStructure& extensions);

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

// Compares sequence numbers as defined by RFC 1982.
int seq_compare(uint32_t seq1, uint32_t seq2);

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

inline bool is_dot3(const uint8_t* ptr, size_t sz) {
    return (sz >= 13 && ptr[12] < 8);
}

} // namespace Internals
} // namespace Tins
/**
 * \endcond
 */

#endif
