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

#include <cstring>
#include <cassert>
#include <algorithm>
#include "arp.h"
#include "ip.h"
#include "ethernetII.h"
#include "rawpdu.h"
#include "constants.h"
#include "network_interface.h"
#include "exceptions.h"


using std::runtime_error;

namespace Tins {

ARP::ARP(ipaddress_type target_ip, ipaddress_type sender_ip, 
  const hwaddress_type &target_hw, const hwaddress_type &sender_hw) 
{
    memset(&_arp, 0, sizeof(arphdr));
    hw_addr_format((uint16_t)Constants::ARP::ETHER);
    prot_addr_format((uint16_t)Constants::Ethernet::IP);
    hw_addr_length(Tins::EthernetII::address_type::address_size);
    prot_addr_length(Tins::IP::address_type::address_size);
    sender_ip_addr(sender_ip);
    target_ip_addr(target_ip);
    sender_hw_addr(sender_hw);
    target_hw_addr(target_hw);
}

ARP::ARP(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(arphdr))
        throw malformed_packet();
    memcpy(&_arp, buffer, sizeof(arphdr));
    total_sz -= sizeof(arphdr);
    //TODO: Check whether this should be removed or not.
    if(total_sz)
        inner_pdu(new RawPDU(buffer + sizeof(arphdr), total_sz));
}

void ARP::sender_hw_addr(const hwaddress_type &new_snd_hw_addr) {
    std::copy(new_snd_hw_addr.begin(), new_snd_hw_addr.end(), _arp.ar_sha);
}

void ARP::sender_ip_addr(ipaddress_type new_snd_ip_addr) {
    this->_arp.ar_sip = new_snd_ip_addr;
}

void ARP::target_hw_addr(const hwaddress_type &new_tgt_hw_addr) {
    std::copy(new_tgt_hw_addr.begin(), new_tgt_hw_addr.end(), _arp.ar_tha);
}

void ARP::target_ip_addr(ipaddress_type new_tgt_ip_addr) {
    this->_arp.ar_tip = new_tgt_ip_addr;
}

void ARP::hw_addr_format(uint16_t new_hw_addr_fmt) {
    this->_arp.ar_hrd = Endian::host_to_be(new_hw_addr_fmt);
}

void ARP::prot_addr_format(uint16_t new_prot_addr_fmt) {
    this->_arp.ar_pro = Endian::host_to_be(new_prot_addr_fmt);
}

void ARP::hw_addr_length(uint8_t new_hw_addr_len) {
    this->_arp.ar_hln = new_hw_addr_len;
}

void ARP::prot_addr_length(uint8_t new_prot_addr_len) {
    this->_arp.ar_pln = new_prot_addr_len;
}

void ARP::opcode(Flags new_opcode) {
    this->_arp.ar_op = Endian::host_to_be<uint16_t>(new_opcode);
}

uint32_t ARP::header_size() const {
    return sizeof(arphdr);
}

void ARP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    #ifdef TINS_DEBUG
    assert(total_sz >= sizeof(arphdr));
    #endif
    memcpy(buffer, &_arp, sizeof(arphdr));
}

bool ARP::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(total_sz < sizeof(arphdr))
        return false;
    const arphdr *arp_ptr = (const arphdr*)ptr;
    return arp_ptr->ar_sip == _arp.ar_tip && arp_ptr->ar_tip == _arp.ar_sip;
}

EthernetII ARP::make_arp_request(ipaddress_type target, ipaddress_type sender, 
const hwaddress_type &hw_snd) 
{
    /* Create ARP packet and set its attributes */
    ARP arp;
    arp.target_ip_addr(target);
    arp.sender_ip_addr(sender);
    arp.sender_hw_addr(hw_snd);
    arp.opcode(REQUEST);

    /* Create the EthernetII PDU with the ARP PDU as its inner PDU */
    return EthernetII(EthernetII::BROADCAST, hw_snd) / arp;
}

EthernetII ARP::make_arp_reply(ipaddress_type target, ipaddress_type sender, 
const hwaddress_type &hw_tgt, const hwaddress_type &hw_snd) 
{
    /* Create ARP packet and set its attributes */
    ARP arp(target, sender, hw_tgt, hw_snd);
    arp.opcode(REPLY);

    /* Create the EthernetII PDU with the ARP PDU as its inner PDU */
    return EthernetII(hw_tgt, hw_snd) / arp;
}
}
