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

#include <sstream>
#include <iostream>
#include <limits>
#include "utils_tests.h"
#include "tins/ethernetII.h"
#include "tins/arp.h"
#include "tins/utils.h"
#include "test_utils.h"

using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::numeric_limits;
using std::ostringstream;

using Tins::PDU;
using Tins::EthernetII;
using Tins::ARP;
using Tins::IPv4Address;
using Tins::HWAddress;
using Tins::Utils::RouteEntry;

ResolveHWAddressTest::ResolveHWAddressTest(const PacketSenderPtr& packet_sender,
                                           const ConfigurationPtr& configuration) 
: ActiveTest(packet_sender, configuration) {
    target_address_ = get_gateway_v4_address(configuration->interface().name());
}

string ResolveHWAddressTest::name() const {
    return "resolve_hwaddress";
}

bool ResolveHWAddressTest::test_matches_packet(const PDU& pdu) const {
    const ARP& arp = pdu.rfind_pdu<ARP>();
    return arp.opcode() == ARP::REPLY && arp.sender_ip_addr() == target_address_;
}

void ResolveHWAddressTest::execute_test() {
    cout << log_prefix() << "trying to resolve " << target_address_ << endl;
    resolved_address_ = Tins::Utils::resolve_hwaddr(configuration().interface(),
                                                    target_address_,
                                                    packet_sender());
    cout << log_prefix() << "address resolved to " << resolved_address_ << endl;
    auto local_ip_address = configuration().interface().ipv4_address();
    auto local_hw_address = configuration().interface().hw_address();
    auto packet = ARP::make_arp_request(target_address_, local_ip_address, local_hw_address);
    packet_sender().send(packet);
}

void ResolveHWAddressTest::validate_packet(const PDU& pdu) {
    const ARP& arp = pdu.rfind_pdu<ARP>();
    if (arp.sender_hw_addr() != resolved_address_) {
        ostringstream oss;
        oss << "Expected address " << resolved_address_ << " but got " << arp.sender_hw_addr();
        throw TestFailed(oss.str());
    }
}
