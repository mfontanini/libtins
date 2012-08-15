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

#include <string>
#include <cstring>
#include <cassert>
#include <algorithm>
#include "arp.h"
#include "ip.h"
#include "ethernetII.h"
#include "rawpdu.h"
#include "utils.h"
#include "constants.h"


using std::string;
using std::runtime_error;

namespace Tins {

ARP::ARP(IPv4Address target_ip, IPv4Address sender_ip, 
  const hwaddress_type &target_hw, const hwaddress_type &sender_hw) 
: PDU(0x0608) 
{
    memset(&_arp, 0, sizeof(arphdr));
    hw_addr_format((uint16_t)Constants::ARP::ETHER);
    prot_addr_format((uint16_t)Constants::Ethernet::IP);
    hw_addr_length(EthernetII::ADDR_SIZE);
    prot_addr_length(IP::ADDR_SIZE);
    sender_ip_addr(sender_ip);
    target_ip_addr(target_ip);
    sender_hw_addr(sender_hw);
    target_hw_addr(target_hw);
}

ARP::ARP(const uint8_t *buffer, uint32_t total_sz) 
: PDU(Utils::to_be<uint16_t>(Constants::Ethernet::ARP)) 
{
    if(total_sz < sizeof(arphdr))
        throw runtime_error("Not enough size for an ARP header in the buffer.");
    memcpy(&_arp, buffer, sizeof(arphdr));
    total_sz -= sizeof(arphdr);
    if(total_sz)
        inner_pdu(new RawPDU(buffer + sizeof(arphdr), total_sz));
}

void ARP::sender_hw_addr(const hwaddress_type &new_snd_hw_addr) {
    std::copy(new_snd_hw_addr.begin(), new_snd_hw_addr.end(), _arp.ar_sha);
}

void ARP::sender_ip_addr(IPv4Address new_snd_ip_addr) {
    this->_arp.ar_sip = new_snd_ip_addr;
}

void ARP::target_hw_addr(const hwaddress_type &new_tgt_hw_addr) {
    std::copy(new_tgt_hw_addr.begin(), new_tgt_hw_addr.end(), _arp.ar_tha);
}

void ARP::target_ip_addr(IPv4Address new_tgt_ip_addr) {
    this->_arp.ar_tip = new_tgt_ip_addr;
}

void ARP::hw_addr_format(uint16_t new_hw_addr_fmt) {
    this->_arp.ar_hrd = Utils::to_be(new_hw_addr_fmt);
}

void ARP::prot_addr_format(uint16_t new_prot_addr_fmt) {
    this->_arp.ar_pro = Utils::to_be(new_prot_addr_fmt);
}

void ARP::hw_addr_length(uint8_t new_hw_addr_len) {
    this->_arp.ar_hln = new_hw_addr_len;
}

void ARP::prot_addr_length(uint8_t new_prot_addr_len) {
    this->_arp.ar_pln = new_prot_addr_len;
}

void ARP::opcode(Flags new_opcode) {
    this->_arp.ar_op = Utils::to_be<uint16_t>(new_opcode);
}

uint32_t ARP::header_size() const {
    return sizeof(arphdr);
}

void ARP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    assert(total_sz >= sizeof(arphdr));
    memcpy(buffer, &_arp, sizeof(arphdr));
}

bool ARP::matches_response(uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(arphdr))
        return false;
    arphdr *arp_ptr = (arphdr*)ptr;
    return arp_ptr->ar_sip == _arp.ar_tip && arp_ptr->ar_tip == _arp.ar_sip;
}

PDU *ARP::clone_packet(const uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(arphdr))
        return 0;
    PDU *child = 0, *cloned;
    if(total_sz > sizeof(arphdr)) {
        child = PDU::clone_inner_pdu(ptr + sizeof(arphdr), total_sz - sizeof(arphdr));
        if(!child)
            return 0;
    }
    cloned = new ARP(ptr, std::min(total_sz, (uint32_t)sizeof(_arp)));
    cloned->inner_pdu(child);
    return cloned;
}

PDU* ARP::make_arp_request(const NetworkInterface& iface, IPv4Address target,
  IPv4Address sender, const hwaddress_type &hw_snd) 
{
    /* Create ARP packet and set its attributes */
    ARP* arp = new ARP();
    arp->target_ip_addr(target);
    arp->sender_ip_addr(sender);
    arp->sender_hw_addr(hw_snd);
    arp->opcode(REQUEST);

    /* Create the EthernetII PDU with the ARP PDU as its inner PDU */
    return new EthernetII(iface, EthernetII::BROADCAST, hw_snd, arp);
}

PDU* ARP::make_arp_reply(const NetworkInterface& iface, IPv4Address target,
  IPv4Address sender, const hwaddress_type &hw_tgt, 
  const hwaddress_type &hw_snd) 
{
    /* Create ARP packet and set its attributes */
    ARP* arp = new ARP(target, sender, hw_tgt, hw_snd);
    arp->opcode(REPLY);

    /* Create the EthernetII PDU with the ARP PDU as its inner PDU */
    EthernetII* eth = new EthernetII(iface, hw_tgt, hw_snd, arp);
    return eth;
}
}
