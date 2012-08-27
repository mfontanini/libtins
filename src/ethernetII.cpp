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
#include <stdexcept>
#include <algorithm>
#ifndef WIN32
    #include <net/ethernet.h>
    #include <netpacket/packet.h>
#endif
#include "ethernetII.h"
#include "rawpdu.h"
#include "ip.h"
#include "arp.h"
#include "utils.h"

namespace Tins {
const EthernetII::address_type EthernetII::BROADCAST("ff:ff:ff:ff:ff:ff");
const size_t EthernetII::ADDR_SIZE(address_type::address_size);

EthernetII::EthernetII(const NetworkInterface& iface, 
  const address_type &dst_hw_addr, const address_type &src_hw_addr, 
  PDU* child) 
: PDU(ETHERTYPE_IP, child)
{
    memset(&_eth, 0, sizeof(ethhdr));
    dst_addr(dst_hw_addr);
    src_addr(src_hw_addr);
    this->iface(iface);
    _eth.payload_type = 0;

}

EthernetII::EthernetII(const uint8_t *buffer, uint32_t total_sz) 
: PDU(ETHERTYPE_IP) 
{
    if(total_sz < sizeof(ethhdr))
        throw std::runtime_error("Not enough size for an ethernetII header in the buffer.");
    memcpy(&_eth, buffer, sizeof(ethhdr));
    PDU *next = 0;
    buffer += sizeof(ethhdr);
    total_sz -= sizeof(ethhdr);
    if(total_sz) {
        switch(payload_type()) {
            case ETHERTYPE_IP:
                next = new Tins::IP(buffer, total_sz);
                break;
            case ETHERTYPE_ARP:
                next = new Tins::ARP(buffer, total_sz);
                break;
            default:
                next = new Tins::RawPDU(buffer, total_sz);
            // Other protos plz
        }
        inner_pdu(next);
    }
}

void EthernetII::dst_addr(const address_type &new_dst_addr) {
    new_dst_addr.copy(_eth.dst_mac);
}

void EthernetII::src_addr(const address_type &new_src_addr) {
    new_src_addr.copy(_eth.src_mac);
}

void EthernetII::iface(const NetworkInterface& new_iface) {
    _iface = new_iface;
}

void EthernetII::payload_type(uint16_t new_payload_type) {
    this->_eth.payload_type = Utils::host_to_be(new_payload_type);
}

uint32_t EthernetII::header_size() const {
    return sizeof(ethhdr);
}

bool EthernetII::send(PacketSender* sender) {
    if(!_iface)
        throw std::runtime_error("Interface has not been set");
    struct sockaddr_ll addr;

    memset(&addr, 0, sizeof(struct sockaddr_ll));

    addr.sll_family = Utils::host_to_be<uint16_t>(PF_PACKET);
    addr.sll_protocol = Utils::host_to_be<uint16_t>(ETH_P_ALL);
    addr.sll_halen = ADDR_SIZE;
    addr.sll_ifindex = _iface.id();
    memcpy(&(addr.sll_addr), _eth.dst_mac, ADDR_SIZE);

    return sender->send_l2(this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
}

bool EthernetII::matches_response(uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(ethhdr))
        return false;
    ethhdr *eth_ptr = (ethhdr*)ptr;
    if(!memcmp(eth_ptr->dst_mac, _eth.src_mac, ADDR_SIZE)) {
        // chequear broadcast en destino original...
        return (inner_pdu()) ? inner_pdu()->matches_response(ptr + sizeof(_eth), total_sz - sizeof(_eth)) : true;
    }
    return false;
}

void EthernetII::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    uint32_t my_sz = header_size();
    assert(total_sz >= my_sz);

    /* Inner type defaults to IP */
    if ((_eth.payload_type == 0) && inner_pdu()) {
        uint16_t type = ETHERTYPE_IP;
        switch (inner_pdu()->pdu_type()) {
            case PDU::IP:
                type = ETHERTYPE_IP;
                break;
            case PDU::ARP:
                type = ETHERTYPE_ARP;
                break;
            default:
                type = 0;
        }
        _eth.payload_type = Utils::host_to_be(type);
    }
    memcpy(buffer, &_eth, sizeof(ethhdr));
}

PDU *EthernetII::recv_response(PacketSender *sender) {
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(struct sockaddr_ll));

    addr.sll_family = Utils::host_to_be<uint16_t>(PF_PACKET);
    addr.sll_protocol = Utils::host_to_be<uint16_t>(ETH_P_ALL);
    addr.sll_halen = ADDR_SIZE;
    addr.sll_ifindex = _iface.id();
    memcpy(&(addr.sll_addr), _eth.dst_mac, ADDR_SIZE);

    return sender->recv_l2(this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
}

PDU *EthernetII::clone_packet(const uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(_eth))
        return 0;
    PDU *child = 0, *cloned;
    if(total_sz > sizeof(_eth)) {
        if((child = PDU::clone_inner_pdu(ptr + sizeof(_eth), total_sz - sizeof(_eth))) == 0)
            return 0;
    }
    cloned = new EthernetII(ptr, std::min(total_sz, (uint32_t)sizeof(_eth)));
    cloned->inner_pdu(child);
    return cloned;
}
}
