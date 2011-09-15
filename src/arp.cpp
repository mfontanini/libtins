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


using namespace std;


Tins::ARP::ARP(uint32_t target_ip, uint32_t sender_ip, const uint8_t *target_hw, const uint8_t *sender_hw) : PDU(0x0608) {
    memset(&_arp, 0, sizeof(arphdr));
    hw_addr_format((uint16_t)Tins::Constants::ARP::ETHER);
    prot_addr_format((uint16_t)Tins::Constants::Ethernet::IP);
    hw_addr_length(EthernetII::ADDR_SIZE);
    prot_addr_length(IP::ADDR_SIZE);
    sender_ip_addr(sender_ip);
    target_ip_addr(target_ip);
    if(sender_hw)
        sender_hw_addr(sender_hw);
    if(target_hw)
        target_hw_addr(target_hw);
}

Tins::ARP::ARP(const uint8_t *buffer, uint32_t total_sz) : PDU(Utils::net_to_host_s(Constants::Ethernet::ARP)) {
    if(total_sz < sizeof(arphdr))
        throw std::runtime_error("Not enough size for an ARP header in the buffer.");
    memcpy(&_arp, buffer, sizeof(arphdr));
    total_sz -= sizeof(arphdr);
    if(total_sz)
        inner_pdu(new RawPDU(buffer + sizeof(arphdr), total_sz));
}

void Tins::ARP::sender_hw_addr(const uint8_t* new_snd_hw_addr) {
    memcpy(this->_arp.ar_sha, new_snd_hw_addr, 6); //Should this use hardware address' length?
}

void Tins::ARP::sender_ip_addr(uint32_t new_snd_ip_addr) {
    this->_arp.ar_sip = new_snd_ip_addr;
}

void Tins::ARP::sender_ip_addr(const string& new_snd_ip_addr) {
    this->_arp.ar_sip = Utils::ip_to_int(new_snd_ip_addr);
}

void Tins::ARP::target_hw_addr(const uint8_t* new_tgt_hw_addr) {
    memcpy(this->_arp.ar_tha, new_tgt_hw_addr, 6); //Should this use hardware address' length?
}

void Tins::ARP::target_ip_addr(uint32_t new_tgt_ip_addr) {
    this->_arp.ar_tip = new_tgt_ip_addr;
}

void Tins::ARP::target_ip_addr(const std::string& new_tgt_ip_addr) {
    this->_arp.ar_tip = Utils::ip_to_int(new_tgt_ip_addr);
}

void Tins::ARP::hw_addr_format(uint16_t new_hw_addr_fmt) {
    this->_arp.ar_hrd = Utils::net_to_host_s(new_hw_addr_fmt);
}

void Tins::ARP::prot_addr_format(uint16_t new_prot_addr_fmt) {
    this->_arp.ar_pro = Utils::net_to_host_s(new_prot_addr_fmt);
}

void Tins::ARP::hw_addr_length(uint8_t new_hw_addr_len) {
    this->_arp.ar_hln = new_hw_addr_len;
}

void Tins::ARP::prot_addr_length(uint8_t new_prot_addr_len) {
    this->_arp.ar_pln = new_prot_addr_len;
}

void Tins::ARP::opcode(Flags new_opcode) {
    this->_arp.ar_op = Utils::net_to_host_s(new_opcode);
}

void Tins::ARP::set_arp_request(const std::string& ip_tgt, const std::string& ip_snd, const uint8_t* hw_snd) {
    this->target_ip_addr(ip_tgt);
    this->sender_ip_addr(ip_snd);
    if (hw_snd)
        this->sender_hw_addr(hw_snd);
    this->opcode(REQUEST);
}

void Tins::ARP::set_arp_reply(const std::string& ip_tgt,
                              const std::string& ip_snd,
                              const uint8_t* hw_tgt,
                              const uint8_t* hw_snd) {

    this->target_ip_addr(ip_tgt);
    this->sender_ip_addr(ip_snd);
    this->sender_hw_addr(hw_snd);
    this->target_hw_addr(hw_tgt);
    this->opcode(REPLY);

}

uint32_t Tins::ARP::header_size() const {
    return sizeof(arphdr);
}

void Tins::ARP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    assert(total_sz >= sizeof(arphdr));
    memcpy(buffer, &_arp, sizeof(arphdr));
}

bool Tins::ARP::matches_response(uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(arphdr))
        return false;
    arphdr *arp_ptr = (arphdr*)ptr;
    return arp_ptr->ar_sip == _arp.ar_tip && arp_ptr->ar_tip == _arp.ar_sip;
}

Tins::PDU *Tins::ARP::clone_packet(const uint8_t *ptr, uint32_t total_sz) {
    if(total_sz < sizeof(arphdr))
        return 0;
    PDU *child = 0, *cloned;
    if(total_sz > sizeof(arphdr)) {
        if((child = PDU::clone_inner_pdu(ptr + sizeof(arphdr), total_sz - sizeof(arphdr))) == 0)
            return 0;
    }
    cloned = new ARP(ptr, std::min(total_sz, (uint32_t)sizeof(_arp)));
    cloned->inner_pdu(child);
    return cloned;
}

Tins::PDU* Tins::ARP::make_arp_request(const string& iface,
                                       const string& target,
                                       const string& sender,
                                       const uint8_t* hw_snd) {
    uint32_t target_ip = Tins::Utils::resolve_ip(target);
    uint32_t sender_ip = Tins::Utils::resolve_ip(sender);
    return make_arp_request(iface, target_ip, sender_ip, hw_snd);
}

Tins::PDU* Tins::ARP::make_arp_request(const std::string& iface,
                                       uint32_t target,
                                       uint32_t sender,
                                       const uint8_t* hw_snd) {

    /* Create ARP packet and set its attributes */
    ARP* arp = new ARP();
    arp->target_ip_addr(target);
    arp->sender_ip_addr(sender);
    if (hw_snd) {
        arp->sender_hw_addr(hw_snd);
    }
    arp->opcode(REQUEST);

    /* Create the EthernetII PDU with the ARP PDU as its inner PDU */
    EthernetII* eth = new EthernetII(iface, Tins::EthernetII::BROADCAST, hw_snd, arp);
    return eth;
}

Tins::PDU* Tins::ARP::make_arp_reply(const string& iface,
                                     const string& target,
                                     const string& sender,
                                     const uint8_t* hw_tgt,
                                     const uint8_t* hw_snd) {

    uint32_t target_ip = Tins::Utils::resolve_ip(target);
    uint32_t sender_ip = Tins::Utils::resolve_ip(sender);
    return make_arp_reply(iface, target_ip, sender_ip, hw_tgt, hw_snd);
}

Tins::PDU* Tins::ARP::make_arp_reply(const string& iface,
                                     uint32_t target,
                                     uint32_t sender,
                                     const uint8_t* hw_tgt,
                                     const uint8_t* hw_snd) {

    /* Create ARP packet and set its attributes */
    ARP* arp = new ARP(target, sender, hw_tgt, hw_snd);
    arp->opcode(REPLY);

    /* Create the EthernetII PDU with the ARP PDU as its inner PDU */
    EthernetII* eth = new EthernetII(iface, hw_tgt, hw_snd, arp);
    return eth;
}

Tins::PDU *Tins::ARP::clone_pdu() const {
    ARP *new_pdu = new ARP();
    new_pdu->copy_fields(this);
    return new_pdu;
}

void Tins::ARP::copy_fields(const ARP *other) {
    std::memcpy(&_arp, &other->_arp, sizeof(_arp));
}
