/*
 * Copyright (c) 2017, Matias Fontanini
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

#include <tins/detail/pdu_helpers.h>
#ifdef TINS_HAVE_PCAP
    #include <pcap.h>
#endif // TINS_HAVE_PCAP
#include <tins/ip.h>
#include <tins/ethernetII.h>
#include <tins/ieee802_3.h>
#include <tins/radiotap.h>
#include <tins/dot11/dot11_base.h>
#include <tins/ipv6.h>
#include <tins/tcp.h>
#include <tins/udp.h>
#include <tins/ipsec.h>
#include <tins/icmp.h>
#include <tins/loopback.h>
#include <tins/sll.h>
#include <tins/ppi.h>
#include <tins/icmpv6.h>
#include <tins/mpls.h>
#include <tins/arp.h>
#include <tins/eapol.h>
#include <tins/rawpdu.h>
#include <tins/dot1q.h>
#include <tins/pppoe.h>
#include <tins/pdu_allocator.h>

namespace Tins {
namespace Internals {

Tins::PDU* pdu_from_flag(Constants::Ethernet::e flag,
                         const uint8_t* buffer,
                         uint32_t size,
                         bool rawpdu_on_no_match) {
    switch (flag) {
        case Tins::Constants::Ethernet::IP:
            return new IP(buffer, size);
        case Constants::Ethernet::IPV6:
            return new IPv6(buffer, size);
        case Tins::Constants::Ethernet::ARP:
            return new ARP(buffer, size);
        case Tins::Constants::Ethernet::PPPOED:
        case Tins::Constants::Ethernet::PPPOES:
            return new PPPoE(buffer, size);
        case Tins::Constants::Ethernet::EAPOL:
            return EAPOL::from_bytes(buffer, size);
        case Tins::Constants::Ethernet::VLAN:
        case Tins::Constants::Ethernet::QINQ:
        case Tins::Constants::Ethernet::OLD_QINQ:
            return new Dot1Q(buffer, size);
        case Tins::Constants::Ethernet::MPLS:
            return new MPLS(buffer, size);
        default:
            {
                PDU* pdu = Internals::allocate<EthernetII>(
                    static_cast<uint16_t>(flag),
                    buffer,
                    size
                );
                if (pdu) {
                    return pdu;
                }
            }
            return rawpdu_on_no_match ? new RawPDU(buffer, size) : 0;
    };
}

Tins::PDU* pdu_from_flag(Constants::IP::e flag,
                         const uint8_t* buffer,
                         uint32_t size,
                         bool rawpdu_on_no_match) {
    switch (flag) {
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
    if (rawpdu_on_no_match) {
        return new Tins::RawPDU(buffer, size);
    }
    return 0;
}

#ifdef TINS_HAVE_PCAP
PDU* pdu_from_dlt_flag(int flag,
                       const uint8_t* buffer,
                       uint32_t size,
                       bool rawpdu_on_no_match) {
    switch (flag) {
        case DLT_EN10MB:
            return new EthernetII(buffer, size);

        #ifdef TINS_HAVE_DOT11
        case DLT_IEEE802_11_RADIO:
            return new RadioTap(buffer, size);
        case DLT_IEEE802_11:
            return Dot11::from_bytes(buffer, size);
        #else // TINS_HAVE_DOT11
        case DLT_IEEE802_11_RADIO:
        case DLT_IEEE802_11:
            throw protocol_disabled();
        #endif // TINS_HAVE_DOT11

        case DLT_NULL:
            return new Loopback(buffer, size);
        case DLT_LINUX_SLL:
            return new SLL(buffer, size);
        case DLT_PPI:
            return new PPI(buffer, size);
        default:
            return rawpdu_on_no_match ? new RawPDU(buffer, size) : 0;
    };
}
#endif // TINS_HAVE_PCAP

Tins::PDU* pdu_from_flag(PDU::PDUType type, const uint8_t* buffer, uint32_t size) {
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
        #ifdef TINS_HAVE_DOT11
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
        #endif // TINS_HAVE_DOT11
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
        case PDU::DOT1AD:
            return Constants::Ethernet::QINQ;
        case PDU::PPPOE:
            return Constants::Ethernet::PPPOED;
        case PDU::MPLS:
            return Constants::Ethernet::MPLS;
        case PDU::RSNEAPOL:
        case PDU::RC4EAPOL:
            return Constants::Ethernet::EAPOL;
        default:
            if (Internals::pdu_type_registered<EthernetII>(flag)) {
                return static_cast<Constants::Ethernet::e>(
                    Internals::pdu_type_to_id<EthernetII>(flag)
                );
            }
            return Constants::Ethernet::UNKNOWN;
    }
}

PDU::PDUType ether_type_to_pdu_flag(Constants::Ethernet::e flag) {
    switch (flag) {
        case Constants::Ethernet::IP:
            return PDU::IP;
        case Constants::Ethernet::IPV6:
            return PDU::IPv6;
        case Constants::Ethernet::ARP:
            return PDU::ARP;
        case Constants::Ethernet::VLAN:
            return PDU::DOT1Q;
        case Constants::Ethernet::QINQ:
        case Constants::Ethernet::OLD_QINQ:
            return PDU::DOT1AD;
        case Constants::Ethernet::PPPOED:
            return PDU::PPPOE;
        //case PDU::RSNEAPOL
        //case PDU::RC4EAPOL:
        //    return Constants::Ethernet::EAPOL;
        default:
            return PDU::UNKNOWN;
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

PDU::PDUType ip_type_to_pdu_flag(Constants::IP::e flag) {
    switch(flag) {
        case Constants::IP::PROTO_IPIP:
            return PDU::IP;
        case Constants::IP::PROTO_IPV6:
            return PDU::IPv6;
        case Constants::IP::PROTO_TCP:
            return PDU::TCP;
        case Constants::IP::PROTO_UDP:
            return PDU::UDP;
        case Constants::IP::PROTO_ICMP:
            return PDU::ICMP;
        case Constants::IP::PROTO_ICMPV6:
            return PDU::ICMPv6;
        case Constants::IP::PROTO_AH:
            return PDU::IPSEC_AH;
        case Constants::IP::PROTO_ESP:
            return PDU::IPSEC_ESP;
        default:
            return PDU::UNKNOWN;
    };
}

} // Internals
} // Tins
