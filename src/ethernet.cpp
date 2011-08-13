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
#include <cstring>

#include <net/ethernet.h>

#include "ethernet.h"
#include "utils.h"

Tins::Ethernet::Ethernet(const uint8_t mac_dst[6], const uint8_t mac_src[6], PDU* child) : PDU(ETHERTYPE_IP, child) {

}

void Tins::Ethernet::dst_mac(uint8_t new_dst_mac[6]) {
    memcpy(this->header.dst_mac, new_dst_mac, 6);
}

void Tins::Ethernet::src_mac(uint8_t new_src_mac[6]) {
    memcpy(this->header.src_mac, new_src_mac, 6);
}

void Tins::Ethernet::crc(uint32_t new_crc) {
    this->_crc = new_crc;
}

uint32_t Tins::Ethernet::header_size() const {
    return sizeof(ethernet_header);
}

uint32_t Tins::Ethernet::trailer_size() const {
    return sizeof(uint32_t);
}

bool Tins::Ethernet::send(PacketSender* sender) {
    return false; //return sender->send_l2(this);
}

void Tins::Ethernet::write_serialization(uint8_t *buffer, uint32_t total_sz, PDU *parent) {
    uint32_t my_sz = header_size() + trailer_size();
    uint32_t new_flag;
    assert(total_sz >= my_sz);
    /*
    if (this->inner_pdu()) {
        new_flag = this->inner_pdu()->flag();

        switch (new_flag) {

        }

    }
    */
    /* This should be replaced by a switch statement */
    this->header.payload_type = ETHERTYPE_IP;
    this->_crc = Tins::Utils::crc32(buffer, total_sz - sizeof(uint32_t));

    memcpy(buffer, &this->header, sizeof(ethernet_header));
    *((uint32_t*)&buffer[total_sz - sizeof(uint32_t)]) = this->_crc;

}
