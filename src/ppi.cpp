/*
 * Copyright (c) 2014, Matias Fontanini
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

#ifdef TINS_DEBUG
    #include <cassert>
#endif // TINS_DEBUG
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

namespace Tins {
PPI::PPI(const uint8_t *buffer, uint32_t total_sz) {
    if(total_sz < sizeof(_header))
        throw malformed_packet();
    std::memcpy(&_header, buffer, sizeof(_header));
    if(length() > total_sz || length() < sizeof(_header))
        throw malformed_packet();
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    // There are some options
    const size_t options_length = length() - sizeof(_header);
    if(options_length > 0) {
        _data.assign(buffer, buffer + options_length);
        buffer += options_length;
        total_sz -= options_length;
    }
    if(total_sz > 0) {
        switch(dlt()) {
            case DLT_IEEE802_11:
                #ifdef HAVE_DOT11
                    inner_pdu(Dot11::from_bytes(buffer, total_sz));
                #else
                    throw protocol_disabled();
                #endif
                break;
            case DLT_EN10MB:
                if(Internals::is_dot3(buffer, total_sz))
                    inner_pdu(new Dot3(buffer, total_sz));
                else
                    inner_pdu(new EthernetII(buffer, total_sz));
                break;
            case DLT_IEEE802_11_RADIO:
                #ifdef HAVE_DOT11
                    inner_pdu(new RadioTap(buffer, total_sz));
                #else
                    throw protocol_disabled();
                #endif
                break;
            case DLT_NULL:
                inner_pdu(new Loopback(buffer, total_sz));
                break;
            case DLT_LINUX_SLL:
                inner_pdu(new Tins::SLL(buffer, total_sz));
                break;
        }
    }
}

uint32_t PPI::header_size() const {
    return sizeof(_header) + _data.size();
}

void PPI::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    throw std::runtime_error("PPI serialization not supported");
}

}
