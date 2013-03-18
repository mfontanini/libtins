/*
 * Copyright (c) 2012, Nasel
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
#include "ipv6.h"
#include "arp.h"
#include "eapol.h"
#include "rawpdu.h"
#include "dot1q.h"

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
            return new Tins::IP(buffer, size);
        case Constants::Ethernet::IPV6:
            return new Tins::IPv6(buffer, size);
        case Tins::Constants::Ethernet::ARP:
            return new Tins::ARP(buffer, size);
        case Tins::Constants::Ethernet::EAPOL:
            return Tins::EAPOL::from_bytes(buffer, size);
        case Tins::Constants::Ethernet::VLAN:
            return new Tins::Dot1Q(buffer, size);
        default:
            return rawpdu_on_no_match ? new RawPDU(buffer, size) : 0;
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
        default:
            return Constants::Ethernet::UNKNOWN;
    }
}
}
}
