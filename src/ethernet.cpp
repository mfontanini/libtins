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

#ifndef WIN32
    #include <net/ethernet.h>
    #include <netpacket/packet.h>
    #include <netinet/in.h>
#endif

#include "ethernet.h"
#include "utils.h"

Tins::Ethernet::Ethernet(const uint8_t* mac_dst, const uint8_t* mac_src, const std::string& iface, PDU* child) throw (std::runtime_error) : PDU(ETHERTYPE_IP, child) {

    this->dst_mac(mac_dst);
    this->src_mac(mac_src);
    this->iface(iface);

}

Tins::Ethernet::Ethernet(const uint8_t* mac_dst, const uint8_t* mac_src, uint32_t iface_index, PDU* child) : PDU(ETHERTYPE_IP, child) {
    this->dst_mac(mac_dst);
    this->src_mac(mac_src);
    this->iface(iface_index);
}

void Tins::Ethernet::dst_mac(const uint8_t* new_dst_mac) {
    memcpy(this->header.dst_mac, new_dst_mac, 6);
}

void Tins::Ethernet::src_mac(const uint8_t* new_src_mac) {
    memcpy(this->header.src_mac, new_src_mac, 6);
}

void Tins::Ethernet::iface(uint32_t new_iface_index) {
    this->_iface_index = new_iface_index;
}

void Tins::Ethernet::iface(const std::string& new_iface) throw (std::runtime_error) {
    if (!Tins::Utils::interface_id(new_iface, this->_iface_index)) {
        throw std::runtime_error("Invalid interface name!");
    }
}

uint32_t Tins::Ethernet::header_size() const {
    return sizeof(ethernet_header);
}

bool Tins::Ethernet::send(PacketSender* sender) {

    struct sockaddr_ll addr;

    memset(&addr, 0, sizeof(struct sockaddr_ll));

    addr.sll_family = Utils::net_to_host_s(PF_PACKET);
    addr.sll_protocol = Utils::net_to_host_s(ETH_P_ALL);
    addr.sll_halen = 6;
    addr.sll_ifindex = this->_iface_index;
    memcpy(&(addr.sll_addr), this->header.dst_mac, 6);

    return sender->send_l2(this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));

}

void Tins::Ethernet::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    uint32_t my_sz = header_size();
    assert(total_sz >= my_sz);
    /*
    if (this->inner_pdu()) {
        new_flag = this->inner_pdu()->flag();

        switch (new_flag) {

        }

    }
    */
    /* This should be replaced by a switch statement */
    this->header.payload_type = Utils::net_to_host_s(ETHERTYPE_IP);

    memcpy(buffer, &this->header, sizeof(ethernet_header));

}
