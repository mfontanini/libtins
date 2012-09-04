/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
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


Tins::SNAP::SNAP(PDU *child) : PDU(0xff, child) {
    std::memset(&_snap, 0, sizeof(_snap));
    _snap.dsap = _snap.ssap = 0xaa;
    _snap.control = 3;
}

Tins::SNAP::SNAP(const uint8_t *buffer, uint32_t total_sz) : PDU(0xff) {
    if(total_sz < sizeof(_snap))
        throw std::runtime_error("Not enough size for a SNAP header in the buffer.");
    std::memcpy(&_snap, buffer, sizeof(_snap));
    buffer += sizeof(_snap);
    total_sz -= sizeof(_snap);
    if(total_sz) {
        switch(eth_type()) {
            case Tins::Constants::Ethernet::IP:
                inner_pdu(new Tins::IP(buffer, total_sz));
                break;
            case Tins::Constants::Ethernet::ARP:
                inner_pdu(new Tins::ARP(buffer, total_sz));
                break;
            case Tins::Constants::Ethernet::EAPOL:
                inner_pdu(Tins::EAPOL::from_bytes(buffer, total_sz));
                break;
        };
    }
}

void Tins::SNAP::control(uint8_t new_control) {
    _snap.control = new_control;
}

void Tins::SNAP::org_code(small_uint<24> new_org) {
    // little endian fix, it was the only way to make it work.
    // check on big endian?
    #ifdef TINS_IS_LITTLE_ENDIAN
        _snap.org_code = Endian::host_to_be<uint32_t>(new_org) >> 8; 
    #else
        _snap.org_code = Endian::host_to_be<uint32_t>(new_org); 
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
        uint16_t type = ETHERTYPE_IP;
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
