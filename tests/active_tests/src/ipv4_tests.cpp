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
#include "ipv4_tests.h"
#include "tins/rawpdu.h"
#include "tins/ethernetII.h"
#include "tins/ip.h"
#include "tins/udp.h"
#include "tins/network_interface.h"

using std::string;
using std::ostringstream;

using Tins::IP;
using Tins::UDP;
using Tins::PDU;
using Tins::RawPDU;
using Tins::EthernetII;
using Tins::PacketSender;
using Tins::NetworkInterface;

// Source address test

IPv4SourceAddressTest::IPv4SourceAddressTest(const PacketSenderPtr& packet_sender,
                                             const ConfigurationPtr& configuration) 
: ActiveTest(packet_sender, configuration) {

}

string IPv4SourceAddressTest::name() const {
    return "ipv4_source_address";
}

void IPv4SourceAddressTest::execute_test() {
    PacketSender& sender = packet_sender();
    Configuration& config = configuration();
    auto packet = IP("8.8.8.8");
    packet /= UDP(config.destination_port(), config.source_port());
    packet /= RawPDU(name());
    sender.send(packet);
}

void IPv4SourceAddressTest::validate_packet(const PDU& pdu) {
    const IP& ip = pdu.rfind_pdu<IP>();
    const NetworkInterface& iface = configuration().interface();
    // The source address should be the same as the default interface's
    if (iface.ipv4_address() != ip.src_addr()) {
        ostringstream oss;
        oss << "Source address should be " << iface.ipv4_address() 
            << " but is " << ip.src_addr();
        throw TestFailed(oss.str());
    }
}

bool IPv4SourceAddressTest::test_matches_packet(const PDU& pdu) const {
    const string& test_name = name();
    RawPDU::payload_type expected_payload(test_name.begin(), test_name.end());
    return pdu.rfind_pdu<RawPDU>().payload() == expected_payload;
}

// Fragmentation test

IPv4FragmentationTest::IPv4FragmentationTest(const PacketSenderPtr& packet_sender,
                                             const ConfigurationPtr& configuration) 
: ActiveTest(packet_sender, configuration) {

}

string IPv4FragmentationTest::name() const {
    return "ipv4_fragmentation";
}

void IPv4FragmentationTest::execute_test() {
    PacketSender& sender = packet_sender();
    Configuration& config = configuration();
    auto packet = IP("8.8.8.8");
    packet /= UDP(config.destination_port(), config.source_port());
    packet /= RawPDU(name());

    IP& ip = packet.rfind_pdu<IP>();
    ip.fragment_offset(100);
    ip.flags(IP::MORE_FRAGMENTS);
    sender.send(packet);
}

void IPv4FragmentationTest::validate_packet(const PDU& pdu) {
    ostringstream oss;
    const IP& ip = pdu.rfind_pdu<IP>();
    if (ip.fragment_offset() != 100) {
        oss << "Expected fragment offset 100 but got " << ip.fragment_offset();
        throw TestFailed(oss.str());
    }
    if (ip.flags() != IP::MORE_FRAGMENTS) {
        oss << "Expected MORE_FRAGMENT flags but got " << (unsigned)ip.flags();
        throw TestFailed(oss.str());
    }
}

bool IPv4FragmentationTest::test_matches_packet(const PDU& pdu) const {
    string test_name = name();
    const RawPDU& raw = pdu.rfind_pdu<RawPDU>();
    string payload(raw.payload().begin(), raw.payload().end());
    return payload.find(test_name) != string::npos;
}

