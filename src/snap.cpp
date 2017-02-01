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

#include <cstring>
#include <stdexcept>
#ifndef _WIN32
    #include <sys/types.h>
    #include <net/ethernet.h>
#endif
#include "snap.h"
#include "constants.h"
#include "arp.h"
#include "ip.h"
#include "eapol.h"
#include "internals.h"
#include "exceptions.h"
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

SNAP::SNAP()
: snap_() {
    snap_.dsap = snap_.ssap = 0xaa;
    control(3);
}

SNAP::SNAP(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(snap_);
    if (stream) {
        inner_pdu(
            Internals::pdu_from_flag(
                (Constants::Ethernet::e)eth_type(), 
                stream.pointer(), 
                stream.size()
            )
        );
    }
}

void SNAP::control(uint8_t new_control) {
    #if TINS_IS_LITTLE_ENDIAN
    snap_.control_org = (snap_.control_org & 0xffffff00) | (new_control);
    #else
    snap_.control_org = (snap_.control_org & 0xffffff) | (new_control << 24);
    #endif
}

void SNAP::org_code(small_uint<24> new_org) {
    #if TINS_IS_LITTLE_ENDIAN
    snap_.control_org = Endian::host_to_be<uint32_t>(new_org) | control();
    #else
    snap_.control_org = new_org | (control() << 24);
    #endif
}

void SNAP::eth_type(uint16_t new_eth) {
    snap_.eth_type = Endian::host_to_be(new_eth); 
}

uint32_t SNAP::header_size() const {
    return sizeof(snap_);
}

void SNAP::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* /*parent*/) {
    OutputMemoryStream stream(buffer, total_sz);
    if (inner_pdu()) {
        Constants::Ethernet::e flag = Internals::pdu_flag_to_ether_type(
            inner_pdu()->pdu_type()
        );
        snap_.eth_type = Endian::host_to_be(
            static_cast<uint16_t>(flag)
        );
    }
    stream.write(snap_);
}

} // Tins
