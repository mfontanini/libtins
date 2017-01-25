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
#include <pcap.h>
#include "dot11/dot11_base.h"
#include "dot3.h"
#include "ethernetII.h"
#include "radiotap.h"
#include "loopback.h"
#include "sll.h"
#include "ppi.h"
#include "internals.h"
#include "exceptions.h"
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;

namespace Tins {

PPI::PPI(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    if (length() > total_sz || length() < sizeof(header_)) {
        throw malformed_packet();
    }
    // There are some options
    const size_t options_length = length() - sizeof(header_);
    if (options_length > 0) {
        stream.read(data_, options_length);
    }
    if (stream) {
        switch (dlt()) {
            case DLT_IEEE802_11:
                #ifdef TINS_HAVE_DOT11
                    parse_80211(stream.pointer(), stream.size());
                #else
                    throw protocol_disabled();
                #endif
                break;
            case DLT_EN10MB:
                if (Internals::is_dot3(stream.pointer(), stream.size())) {
                    inner_pdu(new Dot3(stream.pointer(), stream.size()));
                }
                else {
                    inner_pdu(new EthernetII(stream.pointer(), stream.size()));
                }
                break;
            case DLT_IEEE802_11_RADIO:
                #ifdef TINS_HAVE_DOT11
                    inner_pdu(new RadioTap(stream.pointer(), stream.size()));
                #else
                    throw protocol_disabled();
                #endif
                break;
            case DLT_NULL:
                inner_pdu(new Loopback(stream.pointer(), stream.size()));
                break;
            case DLT_LINUX_SLL:
                inner_pdu(new Tins::SLL(stream.pointer(), stream.size()));
                break;
        }
    }
}

uint32_t PPI::header_size() const {
    return static_cast<uint32_t>(sizeof(header_) + data_.size());
}

void PPI::write_serialization(uint8_t* /*buffer*/, uint32_t /*total_sz*/, const PDU *) {
    throw pdu_not_serializable();
}

void PPI::parse_80211(const uint8_t* buffer, uint32_t total_sz) {
    #ifdef TINS_HAVE_DOT11
    if (data_.size() >= 13) {
        // Is FCS-at-end on?
        if ((data_[12] & 1) == 1) {
            // We need to reduce the total size since we're skipping the FCS
            if (total_sz < sizeof(uint32_t)) {
                throw malformed_packet();
            }
            total_sz -= sizeof(uint32_t);
        }
    }
    inner_pdu(Dot11::from_bytes(buffer, total_sz));
    #endif // TINS_HAVE_DOT11
}

} // Tins
