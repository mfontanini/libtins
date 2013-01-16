/*
 * Copyright (c) 2012, Nasel
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
#include <cassert>
#include <stdexcept>
#ifndef WIN32
    #include <net/ethernet.h>
#endif
#include "snap.h"
#include "constants.h"
#include "arp.h"
#include "ip.h"
#include "eapol.h"
#include "internals.h"


Tins::SNAP::SNAP(PDU *child) : PDU(child) 
{
    std::memset(&_snap, 0, sizeof(_snap));
    _snap.dsap = _snap.ssap = 0xaa;
    control(3);
}

Tins::SNAP::SNAP(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(_snap))
        throw std::runtime_error("Not enough size for a SNAP header in the buffer.");
    std::memcpy(&_snap, buffer, sizeof(_snap));
    buffer += sizeof(_snap);
    total_sz -= sizeof(_snap);
    if(total_sz) {
        /*switch(eth_type()) {
            case Tins::Constants::Ethernet::IP:
                inner_pdu(new Tins::IP(buffer, total_sz));
                break;
            case Tins::Constants::Ethernet::ARP:
                inner_pdu(new Tins::ARP(buffer, total_sz));
                break;
            case Tins::Constants::Ethernet::EAPOL:
                inner_pdu(Tins::EAPOL::from_bytes(buffer, total_sz));
                break;
        };*/
        inner_pdu(
            Internals::pdu_from_flag(
                (Constants::Ethernet::e)eth_type(), 
                buffer, 
                total_sz
            )
        );
    }
}

void Tins::SNAP::control(uint8_t new_control) {
    #if TINS_IS_LITTLE_ENDIAN
    _snap.control_org = (_snap.control_org & 0xffffff00) | (new_control);
    #else
    _snap.control_org = (_snap.control_org & 0xffffff) | (new_control << 24);
    #endif
}

void Tins::SNAP::org_code(small_uint<24> new_org) {
    #if TINS_IS_LITTLE_ENDIAN
    _snap.control_org = Endian::host_to_be<uint32_t>(new_org) | control();
    #else
    _snap.control_org = new_org | (control() << 24);
    #endif
}

void Tins::SNAP::eth_type(uint16_t new_eth) {
    _snap.eth_type = Endian::host_to_be(new_eth); 
}

uint32_t Tins::SNAP::header_size() const {
    return sizeof(_snap);
}

void Tins::SNAP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(_snap));
    if (!_snap.eth_type && inner_pdu()) {
        uint16_t type = Tins::Constants::Ethernet::IP;
        switch (inner_pdu()->pdu_type()) {
            case PDU::IP:
                type = Tins::Constants::Ethernet::IP;
                break;
            case PDU::ARP:
                type = Tins::Constants::Ethernet::ARP;
                break;
            case PDU::EAPOL:
                type = Tins::Constants::Ethernet::EAPOL;
                break;
            default:
                type = 0;
        }
        _snap.eth_type = Endian::host_to_be(type);
    }
    std::memcpy(buffer, &_snap, sizeof(_snap));
}
