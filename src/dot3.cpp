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
    #include <net/ethernet.h>
    #include <netinet/in.h>
#endif
#include "dot3.h"
#include "packet_sender.h"
#include "llc.h"
#include "exceptions.h"

namespace Tins {
const Dot3::address_type Dot3::BROADCAST("ff:ff:ff:ff:ff:ff");

Dot3::Dot3(const address_type &dst_hw_addr, const address_type &src_hw_addr)
{
    memset(&_eth, 0, sizeof(ethhdr));
    this->dst_addr(dst_hw_addr);
    this->src_addr(src_hw_addr);
    this->_eth.length = 0;

}

Dot3::Dot3(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(ethhdr))
        throw malformed_packet();
    memcpy(&_eth, buffer, sizeof(ethhdr));
    buffer += sizeof(ethhdr);
    total_sz -= sizeof(ethhdr);
    if(total_sz)
        inner_pdu(new Tins::LLC(buffer, total_sz));
}

void Dot3::dst_addr(const address_type &new_dst_mac) {
    std::copy(new_dst_mac.begin(), new_dst_mac.end(), _eth.dst_mac);
}

void Dot3::src_addr(const address_type &new_src_mac) {
    std::copy(new_src_mac.begin(), new_src_mac.end(), _eth.src_mac);
}

void Dot3::length(uint16_t new_length) {
    this->_eth.length = Endian::host_to_be(new_length);
}

uint32_t Dot3::header_size() const {
    return sizeof(ethhdr);
}

#ifndef WIN32
void Dot3::send(PacketSender &sender, const NetworkInterface &iface) {
    if(!iface)
        throw invalid_interface();
        
    #if !defined(BSD) && !defined(__FreeBSD_kernel__)
        struct sockaddr_ll addr;

        memset(&addr, 0, sizeof(struct sockaddr_ll));

        addr.sll_family = Endian::host_to_be<uint16_t>(PF_PACKET);
        addr.sll_protocol = Endian::host_to_be<uint16_t>(ETH_P_ALL);
        addr.sll_halen = address_type::address_size;
        addr.sll_ifindex = iface.id();
        memcpy(&(addr.sll_addr), _eth.dst_mac, sizeof(_eth.dst_mac));

        sender.send_l2(*this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
    #else
        sender.send_l2(*this, 0, 0, iface);
    #endif
}
#endif // WIN32

bool Dot3::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(total_sz < sizeof(ethhdr))
        return false;
    const size_t addr_sz = address_type::address_size;
    const ethhdr *eth_ptr = (const ethhdr*)ptr;
    if(std::equal(_eth.src_mac, _eth.src_mac + addr_sz, eth_ptr->dst_mac)) {
        if(std::equal(_eth.src_mac, _eth.src_mac + addr_sz, eth_ptr->dst_mac) || dst_addr() == BROADCAST)
        {
            ptr += sizeof(ethhdr);
            total_sz -= sizeof(ethhdr);
            return inner_pdu() ? inner_pdu()->matches_response(ptr, total_sz) : true;
        }
    }
    return false;
}

void Dot3::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    #ifdef TINS_DEBUG
    assert(total_sz >= header_size());
    #endif
    _eth.length = Endian::host_to_be<uint16_t>(size() - sizeof(_eth));

    memcpy(buffer, &_eth, sizeof(ethhdr));
}

#ifndef WIN32
PDU *Dot3::recv_response(PacketSender &sender, const NetworkInterface &iface) {
    if(!iface)
        throw invalid_interface();
    #if !defined(BSD) && !defined(__FreeBSD_kernel__)
        struct sockaddr_ll addr;
        memset(&addr, 0, sizeof(struct sockaddr_ll));

        addr.sll_family = Endian::host_to_be<uint16_t>(PF_PACKET);
        addr.sll_protocol = Endian::host_to_be<uint16_t>(ETH_P_802_3);
        addr.sll_halen = address_type::address_size;
        addr.sll_ifindex = iface.id();
        memcpy(&(addr.sll_addr), _eth.dst_mac, sizeof(_eth.dst_mac));

        return sender.recv_l2(*this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
    #else
        return sender.recv_l2(*this, 0, 0, iface);
    #endif
}
#endif // WIN32
}
