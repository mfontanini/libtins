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

#include <tins/utils/pdu_utils.h>

using std::string;

namespace Tins {
namespace Utils {

string to_string(PDU::PDUType pduType) {
#define ENUM_TEXT(p) case(PDU::p): return #p;
    switch (pduType){
        ENUM_TEXT(RAW);
        ENUM_TEXT(ETHERNET_II);
        ENUM_TEXT(IEEE802_3);
        ENUM_TEXT(RADIOTAP);
        ENUM_TEXT(DOT11);
        ENUM_TEXT(DOT11_ACK);
        ENUM_TEXT(DOT11_ASSOC_REQ);
        ENUM_TEXT(DOT11_ASSOC_RESP);
        ENUM_TEXT(DOT11_AUTH);
        ENUM_TEXT(DOT11_BEACON);
        ENUM_TEXT(DOT11_BLOCK_ACK);
        ENUM_TEXT(DOT11_BLOCK_ACK_REQ);
        ENUM_TEXT(DOT11_CF_END);
        ENUM_TEXT(DOT11_DATA);
        ENUM_TEXT(DOT11_CONTROL);
        ENUM_TEXT(DOT11_DEAUTH);
        ENUM_TEXT(DOT11_DIASSOC);
        ENUM_TEXT(DOT11_END_CF_ACK);
        ENUM_TEXT(DOT11_MANAGEMENT);
        ENUM_TEXT(DOT11_PROBE_REQ);
        ENUM_TEXT(DOT11_PROBE_RESP);
        ENUM_TEXT(DOT11_PS_POLL);
        ENUM_TEXT(DOT11_REASSOC_REQ);
        ENUM_TEXT(DOT11_REASSOC_RESP);
        ENUM_TEXT(DOT11_RTS);
        ENUM_TEXT(DOT11_QOS_DATA);
        ENUM_TEXT(LLC);
        ENUM_TEXT(SNAP);
        ENUM_TEXT(IP);
        ENUM_TEXT(ARP);
        ENUM_TEXT(TCP);
        ENUM_TEXT(UDP);
        ENUM_TEXT(ICMP);
        ENUM_TEXT(BOOTP);
        ENUM_TEXT(DHCP);
        ENUM_TEXT(EAPOL);
        ENUM_TEXT(RC4EAPOL);
        ENUM_TEXT(RSNEAPOL);
        ENUM_TEXT(DNS);
        ENUM_TEXT(LOOPBACK);
        ENUM_TEXT(IPv6);
        ENUM_TEXT(ICMPv6);
        ENUM_TEXT(SLL);
        ENUM_TEXT(DHCPv6);
        ENUM_TEXT(DOT1AD);
        ENUM_TEXT(DOT1Q);
        ENUM_TEXT(PPPOE);
        ENUM_TEXT(STP);
        ENUM_TEXT(PPI);
        ENUM_TEXT(IPSEC_AH);
        ENUM_TEXT(IPSEC_ESP);
        ENUM_TEXT(PKTAP);
        ENUM_TEXT(MPLS);
        ENUM_TEXT(USER_DEFINED_PDU);
        default: 
            return "";
    }
#undef ENUM_TEXT
}

} // Utils
} // Tins
