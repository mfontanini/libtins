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
#endif
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include "macros.h"
#ifndef WIN32
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <net/if_dl.h>
    #else
        #include <netpacket/packet.h>
    #endif
    #include <netinet/in.h>
    #include <net/ethernet.h>
#endif
#include "ethernetII.h"
#include "packet_sender.h"
#include "rawpdu.h"
#include "ip.h"
#include "ipv6.h"
#include "arp.h"
#include "constants.h"
#include "internals.h"
#include "exceptions.h"

namespace Tins {
const EthernetII::address_type EthernetII::BROADCAST("ff:ff:ff:ff:ff:ff");

EthernetII::EthernetII(const address_type &dst_hw_addr, 
const address_type &src_hw_addr) 
{
    memset(&_eth, 0, sizeof(ethhdr));
    dst_addr(dst_hw_addr);
    src_addr(src_hw_addr);
    _eth.payload_type = 0;

}

EthernetII::EthernetII(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(ethhdr))
        throw malformed_packet();
    memcpy(&_eth, buffer, sizeof(ethhdr));
    buffer += sizeof(ethhdr);
    total_sz -= sizeof(ethhdr);
    if(total_sz) {
        inner_pdu(
            Internals::pdu_from_flag(
                (Constants::Ethernet::e)payload_type(), 
                buffer, 
                total_sz
            )
        );
    }

}

void EthernetII::dst_addr(const address_type &new_dst_addr) {
    new_dst_addr.copy(_eth.dst_mac);
}

void EthernetII::src_addr(const address_type &new_src_addr) {
    new_src_addr.copy(_eth.src_mac);
}

void EthernetII::payload_type(uint16_t new_payload_type) {
    this->_eth.payload_type = Endian::host_to_be(new_payload_type);
}

uint32_t EthernetII::header_size() const {

    return sizeof(ethhdr);
}

uint32_t EthernetII::trailer_size() const {
    int32_t padding = 60 - sizeof(ethhdr); // EthernetII min size is 60, padding is sometimes needed
    if (inner_pdu()) {
        padding -= inner_pdu()->size();
        padding = std::max(0, padding);
    }
    return padding;
}

#ifndef WIN32
void EthernetII::send(PacketSender &sender, const NetworkInterface &iface) {
    if(!iface)
        throw invalid_interface();
    
    #if !defined(BSD) && !defined(__FreeBSD_kernel__)
        struct sockaddr_ll addr;

        memset(&addr, 0, sizeof(struct sockaddr_ll));

        addr.sll_family = Endian::host_to_be<uint16_t>(PF_PACKET);
        addr.sll_protocol = Endian::host_to_be<uint16_t>(ETH_P_ALL);
        addr.sll_halen = address_type::address_size;
        addr.sll_ifindex = iface.id();
        memcpy(&(addr.sll_addr), _eth.dst_mac, address_type::address_size);

        sender.send_l2(*this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
    #else
        sender.send_l2(*this, 0, 0, iface);
    #endif
}
#endif // WIN32

bool EthernetII::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(total_sz < sizeof(ethhdr))
        return false;
    const size_t addr_sz = address_type::address_size;
    const ethhdr *eth_ptr = (const ethhdr*)ptr;
    if(std::equal(_eth.src_mac, _eth.src_mac + addr_sz, eth_ptr->dst_mac)) {
        if(std::equal(_eth.src_mac, _eth.src_mac + addr_sz, eth_ptr->dst_mac) || !dst_addr().is_unicast())
        {
            return (inner_pdu()) ? inner_pdu()->matches_response(ptr + sizeof(_eth), total_sz - sizeof(_eth)) : true;
        }
    }
    return false;
}

void EthernetII::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    #ifdef TINS_DEBUG
    assert(total_sz >= header_size() + trailer_size());
    #endif

    /* Inner type defaults to IP */
    if (inner_pdu()) {
        Constants::Ethernet::e flag = Internals::pdu_flag_to_ether_type(
            inner_pdu()->pdu_type()
        );
        payload_type(static_cast<uint16_t>(flag));
    }
    memcpy(buffer, &_eth, sizeof(ethhdr));
    uint32_t trailer = trailer_size();
    if (trailer) {
        uint32_t trailer_offset = header_size();
        if (inner_pdu())
            trailer_offset += inner_pdu()->size();
        memset(buffer + trailer_offset, 0, trailer);
    }

}

#ifndef WIN32
PDU *EthernetII::recv_response(PacketSender &sender, const NetworkInterface &iface) {
    #if !defined(BSD) && !defined(__FreeBSD_kernel__)
        struct sockaddr_ll addr;
        memset(&addr, 0, sizeof(struct sockaddr_ll));

        addr.sll_family = Endian::host_to_be<uint16_t>(PF_PACKET);
        addr.sll_protocol = Endian::host_to_be<uint16_t>(ETH_P_ALL);
        addr.sll_halen = address_type::address_size;
        addr.sll_ifindex = iface.id();
        memcpy(&(addr.sll_addr), _eth.dst_mac, address_type::address_size);

        return sender.recv_l2(*this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
    #else
        return sender.recv_l2(*this, 0, 0, iface);
    #endif
}
#endif // WIN32
}
