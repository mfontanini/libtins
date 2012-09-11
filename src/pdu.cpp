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

#include <cassert>
#include "pdu.h"
#include "rawpdu.h"
#include "packet_sender.h"

namespace Tins {

PDU::PDU(uint32_t flag, PDU *next_pdu) : _flag(flag), _inner_pdu(next_pdu) {

}

PDU::PDU(const PDU &other) : _inner_pdu(0) {
    _flag = other.flag();
    copy_inner_pdu(other);
}

PDU &PDU::operator=(const PDU &other) {
    _flag = other.flag();
    copy_inner_pdu(other);
    return *this;
}

PDU::~PDU() {
    delete _inner_pdu;
}

void PDU::copy_inner_pdu(const PDU &pdu) {
    if(pdu.inner_pdu())
        inner_pdu(pdu.inner_pdu()->clone_pdu());
}

uint32_t PDU::size() const {
    uint32_t sz = header_size() + trailer_size();
    const PDU *ptr(_inner_pdu);
    while(ptr) {
        sz += ptr->header_size() + ptr->trailer_size();
        ptr = ptr->inner_pdu();
    }
    return sz;
}

bool PDU::send(PacketSender &) { 
    return false; 
}

PDU *PDU::recv_response(PacketSender &) { 
    return false; 
}

void PDU::flag(uint32_t new_flag) {
    _flag = new_flag;
}

void PDU::inner_pdu(PDU *next_pdu) {
    delete _inner_pdu;
    _inner_pdu = next_pdu;
}

PDU *PDU::release_inner_pdu() {
    PDU *result = 0;
    std::swap(result, _inner_pdu);
    return result;
}

PDU::serialization_type PDU::serialize() {
    std::vector<uint8_t> buffer(size());
    serialize(&buffer[0], buffer.size(), 0);
    
    // Copy elision, do your magic
    return buffer;
}

void PDU::serialize(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    uint32_t sz = header_size() + trailer_size();
    /* Must not happen... */
    assert(total_sz >= sz);
    if(_inner_pdu)
        _inner_pdu->serialize(buffer + header_size(), total_sz - sz, this);
    write_serialization(buffer, total_sz, parent);
}

PDU *PDU::clone_inner_pdu(const uint8_t *ptr, uint32_t total_sz) {
    PDU *child = 0;
    if(inner_pdu()) {
        child = inner_pdu()->clone_packet(ptr, total_sz);
        if(!child)
            return 0;
    }
    else
        child = new RawPDU(ptr, total_sz);
    return child;
}

PDU *PDU::clone_packet() const {
    PDU *ret = clone_pdu();
    if(ret) {
        PDU *ptr = 0, *last = ret;
        while(last && last->inner_pdu()) {
            ptr = last->inner_pdu()->clone_pdu();
            last->inner_pdu(ptr);
            last = ptr;
        }
    }
    return ret;
}
}
