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
    _snap.id = 3;
}

Tins::SNAP::SNAP(const uint8_t *buffer, uint32_t total_sz) : PDU(0xff) {
    if(total_sz < sizeof(_snap))
        throw std::runtime_error("Not enough size for a SNAP header in the buffer.");
    std::memcpy(&_snap, buffer, sizeof(_snap));
    buffer += sizeof(_snap);
    total_sz -= sizeof(_snap);
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

Tins::SNAP::SNAP(const SNAP &other) : PDU(other) {
    copy_fields(&other);
}

Tins::SNAP &Tins::SNAP::operator=(const SNAP &other) {
    copy_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

void Tins::SNAP::id(uint8_t new_id) {
    _snap.id = new_id;
}

void Tins::SNAP::poll(uint8_t new_poll) {
    _snap.poll = new_poll;
}

void Tins::SNAP::org_code(uint32_t new_org) {
    _snap.org_code = new_org;
}

void Tins::SNAP::eth_type(uint32_t new_eth) {
    _snap.eth_type = Utils::net_to_host_s(new_eth);
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
        _snap.eth_type = Utils::net_to_host_s(type);
    }
    std::memcpy(buffer, &_snap, sizeof(_snap));
}

void Tins::SNAP::copy_fields(const SNAP *other) {
    std::memcpy(&_snap, &other->_snap, sizeof(_snap));
}

Tins::PDU *Tins::SNAP::clone_pdu() const {
    SNAP *new_pdu = new SNAP();
    new_pdu->copy_fields(this);
    return new_pdu;
}
