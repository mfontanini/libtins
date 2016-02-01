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

#ifndef _WIN32
    #include <sys/socket.h>
    #ifdef BSD
        #include <net/if_dl.h>
        #include <netinet/in.h>
        #include <net/ethernet.h>
    #endif
#else
    #include <ws2tcpip.h>
#endif
#include <stdexcept>
#include <cstring>
#include "loopback.h"
#include "packet_sender.h"
#include "ip.h"
#include "llc.h"
#include "rawpdu.h"
#include "exceptions.h"
#include "memory_helpers.h"

#if !defined(PF_LLC)
    // compilation fix, nasty but at least works on BSD
    #define PF_LLC 26
#endif

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

Loopback::Loopback()
: family_() {
    
}

Loopback::Loopback(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    family_ = stream.read<uint32_t>();
    #ifndef _WIN32
    if (total_sz) {
        switch (family_) {
            case PF_INET:
                inner_pdu(new Tins::IP(stream.pointer(), stream.size()));
                break;
            case PF_LLC:
                inner_pdu(new Tins::LLC(stream.pointer(), stream.size()));
                break;
            default:
                inner_pdu(new Tins::RawPDU(stream.pointer(), stream.size()));
                break;
        };
    }
    #endif // _WIN32
}
    
void Loopback::family(uint32_t family_id) {
    family_ = family_id;
}

uint32_t Loopback::header_size() const {
    return sizeof(family_);
}

void Loopback::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    OutputMemoryStream stream(buffer, total_sz);
    #ifndef _WIN32
    if (tins_cast<const Tins::IP*>(inner_pdu())) {
        family_ = PF_INET;
    }
    else if (tins_cast<const Tins::LLC*>(inner_pdu())) {
        family_ = PF_LLC;
    }
    stream.write(family_);
    #endif // _WIN32
}

bool Loopback::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(family_)) {
        return false;
    }
    // If there's an inner_pdu, check if the inner pdu matches.
    // Otherwise, just check this loopback family.
    
    return inner_pdu() ? 
           inner_pdu()->matches_response(ptr + sizeof(family_), total_sz - sizeof(family_)) :
           (family_ == *reinterpret_cast<const uint32_t*>(ptr));
}

#ifdef BSD
void Loopback::send(PacketSender& sender, const NetworkInterface& iface) {
    if (!iface) {
        throw invalid_interface();
    }
    
    sender.send_l2(*this, 0, 0, iface);
}
#endif // _WIN32

} // Tins
