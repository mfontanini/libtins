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

#include "internals.h"
#include "ip.h"
#include "ethernetII.h"
#include "ieee802_3.h"
#include "radiotap.h"
#include "dot11/dot11_base.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "ipsec.h"
#include "icmp.h"
#include "icmpv6.h"
#include "arp.h"
#include "eapol.h"
#include "rawpdu.h"
#include "dot1q.h"
#include "pppoe.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "pdu_allocator.h"

using std::string;

namespace Tins {
namespace Internals {
bool from_hex(const string &str, uint32_t &result) {
    unsigned i(0);
    result = 0;
    while(i < str.size()) {
        uint8_t tmp;
        if(str[i] >= 'A' && str[i] <= 'F')
            tmp = (str[i] - 'A' + 10);
        else if(str[i] >= '0' && str[i] <= '9')
            tmp = (str[i] - '0');
        else
            return false;
        result = (result << 4) | tmp;
        i++;
    }
    return true;
}

void skip_line(std::istream &input) {
    int c = 0;
    while(c != '\n' && input)
         c = input.get();
}

Tins::PDU *pdu_from_flag(Constants::Ethernet::e flag, const uint8_t *buffer, 
  uint32_t size, bool rawpdu_on_no_match) 
{
    switch(flag) {
        case Tins::Constants::Ethernet::IP:
            return new IP(buffer, size);
        case Constants::Ethernet::IPV6:
            return new IPv6(buffer, size);
        case Tins::Constants::Ethernet::ARP:
            return new ARP(buffer, size);
        case Tins::Constants::Ethernet::PPPOED:
            return new PPPoE(buffer, size);
        case Tins::Constants::Ethernet::EAPOL:
            return EAPOL::from_bytes(buffer, size);
        case Tins::Constants::Ethernet::VLAN:
            return new Dot1Q(buffer, size);
        default:
            {
                PDU *pdu = Internals::allocate<EthernetII>(
                    static_cast<uint16_t>(flag),
                    buffer, 
                    size
                );
                if(pdu)
                    return pdu;
            }
            return rawpdu_on_no_match ? new RawPDU(buffer, size) : 0;
    };
}

Tins::PDU *pdu_from_flag(Constants::IP::e flag, const uint8_t *buffer, 
  uint32_t size, bool rawpdu_on_no_match) 
{
    switch(flag) {
        case Constants::IP::PROTO_IPIP:
            return new Tins::IP(buffer, size);
        case Constants::IP::PROTO_TCP:
            return new Tins::TCP(buffer, size);
        case Constants::IP::PROTO_UDP:
            return new Tins::UDP(buffer, size);
        case Constants::IP::PROTO_ICMP:
            return new Tins::ICMP(buffer, size);
        case Constants::IP::PROTO_ICMPV6:
            return new Tins::ICMPv6(buffer, size);
        case Constants::IP::PROTO_IPV6:
            return new Tins::IPv6(buffer, size);
        case Constants::IP::PROTO_AH:
            return new Tins::IPSecAH(buffer, size);
        case Constants::IP::PROTO_ESP:
            return new Tins::IPSecESP(buffer, size);
        default:
            break;
    }
    if(rawpdu_on_no_match)
        return new Tins::RawPDU(buffer, size);
    return 0;
}

Tins::PDU *pdu_from_flag(PDU::PDUType type, const uint8_t *buffer, uint32_t size) 
{
    switch(type) {
        case Tins::PDU::ETHERNET_II:
            return new Tins::EthernetII(buffer, size);
        case Tins::PDU::IP:
            return new Tins::IP(buffer, size);
        case Tins::PDU::IPv6:
            return new Tins::IPv6(buffer, size);
        case Tins::PDU::ARP:
            return new Tins::ARP(buffer, size);
        case Tins::PDU::IEEE802_3:
            return new Tins::IEEE802_3(buffer, size);
        case Tins::PDU::PPPOE:
            return new Tins::PPPoE(buffer, size);
        #ifdef HAVE_DOT11
            case Tins::PDU::RADIOTAP:
                return new Tins::RadioTap(buffer, size);
            case Tins::PDU::DOT11:
            case Tins::PDU::DOT11_ACK:
            case Tins::PDU::DOT11_ASSOC_REQ:
            case Tins::PDU::DOT11_ASSOC_RESP:
            case Tins::PDU::DOT11_AUTH:
            case Tins::PDU::DOT11_BEACON:
            case Tins::PDU::DOT11_BLOCK_ACK:
            case Tins::PDU::DOT11_BLOCK_ACK_REQ:
            case Tins::PDU::DOT11_CF_END:
            case Tins::PDU::DOT11_DATA:
            case Tins::PDU::DOT11_CONTROL:
            case Tins::PDU::DOT11_DEAUTH:
            case Tins::PDU::DOT11_DIASSOC:
            case Tins::PDU::DOT11_END_CF_ACK:
            case Tins::PDU::DOT11_MANAGEMENT:
            case Tins::PDU::DOT11_PROBE_REQ:
            case Tins::PDU::DOT11_PROBE_RESP:
            case Tins::PDU::DOT11_PS_POLL:
            case Tins::PDU::DOT11_REASSOC_REQ:
            case Tins::PDU::DOT11_REASSOC_RESP:
            case Tins::PDU::DOT11_RTS:
            case Tins::PDU::DOT11_QOS_DATA:
                return Tins::Dot11::from_bytes(buffer, size);
        #endif // HAVE_DOT11
        default:
            return 0;
    };
}

Constants::Ethernet::e pdu_flag_to_ether_type(PDU::PDUType flag) {
    switch (flag) {
        case PDU::IP:
            return Constants::Ethernet::IP;
        case PDU::IPv6:
            return Constants::Ethernet::IPV6;
        case PDU::ARP:
            return Constants::Ethernet::ARP;
        case PDU::DOT1Q:
            return Constants::Ethernet::VLAN;
        case PDU::PPPOE:
            return Constants::Ethernet::PPPOED;
        default:
            if(Internals::pdu_type_registered<EthernetII>(flag)) 
                return static_cast<Constants::Ethernet::e>(
                    Internals::pdu_type_to_id<EthernetII>(flag)
                );
            return Constants::Ethernet::UNKNOWN;
    }
}

Constants::IP::e pdu_flag_to_ip_type(PDU::PDUType flag) {
    switch(flag) {
        case PDU::IP:
            return Constants::IP::PROTO_IPIP;
        case PDU::IPv6:
            return Constants::IP::PROTO_IPV6;
        case PDU::TCP:
            return Constants::IP::PROTO_TCP;
        case PDU::UDP:
            return Constants::IP::PROTO_UDP;
        case PDU::ICMP:
            return Constants::IP::PROTO_ICMP;
        case PDU::ICMPv6:
            return Constants::IP::PROTO_ICMPV6;
        case PDU::IPSEC_AH:
            return Constants::IP::PROTO_AH;
        case PDU::IPSEC_ESP:
            return Constants::IP::PROTO_ESP;
        default:
            return static_cast<Constants::IP::e>(0xff);
    };
}

bool increment(IPv4Address &addr) {
    uint32_t addr_int = Endian::be_to_host<uint32_t>(addr);
    bool reached_end = ++addr_int == 0xffffffff;
    addr = IPv4Address(Endian::be_to_host<uint32_t>(addr_int));
    return reached_end;
}

bool increment(IPv6Address &addr) {
    return increment_buffer(addr);
}

bool decrement(IPv4Address &addr) {
    uint32_t addr_int = Endian::be_to_host<uint32_t>(addr);
    bool reached_end = --addr_int == 0;
    addr = IPv4Address(Endian::be_to_host<uint32_t>(addr_int));
    return reached_end;
}

bool decrement(IPv6Address &addr) {
    return decrement_buffer(addr);
}

IPv4Address last_address_from_mask(IPv4Address addr, IPv4Address mask) {
    uint32_t addr_int = Endian::be_to_host<uint32_t>(addr),
            mask_int = Endian::be_to_host<uint32_t>(mask);
    return IPv4Address(Endian::host_to_be(addr_int | ~mask_int));
}

IPv6Address last_address_from_mask(IPv6Address addr, const IPv6Address &mask) {
    IPv6Address::iterator addr_iter = addr.begin();
    for(IPv6Address::const_iterator it = mask.begin(); it != mask.end(); ++it, ++addr_iter) {
        *addr_iter = *addr_iter | ~*it;
    }
    return addr;
}
} // namespace Internals
} // namespace Tins
