/*
 * Copyright (c) 2016, Matias Fontanini
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
#include <algorithm>
#include "arp.h"
#include "ip.h"
#include "ethernetII.h"
#include "rawpdu.h"
#include "constants.h"
#include "network_interface.h"
#include "exceptions.h"
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PDU::metadata ARP::extract_metadata(const uint8_t* /*buffer*/, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(arp_header))) {
        throw malformed_packet();
    }
    return metadata(sizeof(arp_header), pdu_flag, PDU::UNKNOWN);
}

ARP::ARP(ipaddress_type target_ip, 
         ipaddress_type sender_ip, 
         const hwaddress_type& target_hw, 
         const hwaddress_type& sender_hw) 
: header_() {
    hw_addr_format((uint16_t)Constants::ARP::ETHER);
    prot_addr_format((uint16_t)Constants::Ethernet::IP);
    hw_addr_length(Tins::EthernetII::address_type::address_size);
    prot_addr_length(Tins::IP::address_type::address_size);
    sender_ip_addr(sender_ip);
    target_ip_addr(target_ip);
    sender_hw_addr(sender_hw);
    target_hw_addr(target_hw);
}

ARP::ARP(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    if (stream) {
        inner_pdu(new RawPDU(stream.pointer(), stream.size()));
    }
}

void ARP::sender_hw_addr(const hwaddress_type& address) {
    address.copy(header_.sender_hw_address);
}

void ARP::sender_ip_addr(ipaddress_type address) {
    header_.sender_ip_address = address;
}

void ARP::target_hw_addr(const hwaddress_type& address) {
    address.copy(header_.target_hw_address);
}

void ARP::target_ip_addr(ipaddress_type address) {
    header_.target_ip_address = address;
}

void ARP::hw_addr_format(uint16_t format) {
    header_.hw_address_format = Endian::host_to_be(format);
}

void ARP::prot_addr_format(uint16_t format) {
    header_.proto_address_format = Endian::host_to_be(format);
}

void ARP::hw_addr_length(uint8_t length) {
    header_.hw_address_length = length;
}

void ARP::prot_addr_length(uint8_t length) {
    header_.proto_address_length = length;
}

void ARP::opcode(Flags code) {
    header_.opcode = Endian::host_to_be<uint16_t>(code);
}

uint32_t ARP::header_size() const {
    return sizeof(header_);
}

void ARP::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *) {
    OutputMemoryStream stream(buffer, total_sz);
    stream.write(header_);
}

bool ARP::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(header_)) {
        return false;
    }
    const arp_header* arp_ptr = (const arp_header*)ptr;
    return arp_ptr->sender_ip_address == header_.target_ip_address && 
           arp_ptr->target_ip_address == header_.sender_ip_address;
}

EthernetII ARP::make_arp_request(ipaddress_type target, 
                                 ipaddress_type sender, 
                                 const hwaddress_type& hw_snd) {
    // Create ARP packet and set its attributes
    ARP arp;
    arp.target_ip_addr(target);
    arp.sender_ip_addr(sender);
    arp.sender_hw_addr(hw_snd);
    arp.opcode(REQUEST);

    // Create the EthernetII PDU with the ARP PDU as its inner PDU
    return EthernetII(EthernetII::BROADCAST, hw_snd) / arp;
}

EthernetII ARP::make_arp_reply(ipaddress_type target, 
                               ipaddress_type sender, 
                               const hwaddress_type& hw_tgt, 
                               const hwaddress_type& hw_snd)  {
    // Create ARP packet and set its attributes
    ARP arp(target, sender, hw_tgt, hw_snd);
    arp.opcode(REPLY);

    // Create the EthernetII PDU with the ARP PDU as its inner PDU
    return EthernetII(hw_tgt, hw_snd) / arp;
}

} // Tins
