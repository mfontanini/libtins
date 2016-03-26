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

#include <random>
#include <iostream>
#include "tcp_tests.h"
#include "tins/tcp.h"
#include "tins/ip.h"
#include "tins/ethernetII.h"
#include "tins/utils.h"
#include "test_utils.h"

using std::string;
using std::cout;
using std::endl;
using std::random_device;

using Tins::PDU;
using Tins::TCP;
using Tins::IP;
using Tins::IPv4Address;
using Tins::NetworkInterface;
using Tins::EthernetII;
using Tins::Utils::resolve_domain;

TCPSynTest::TCPSynTest(const PacketSenderPtr& packet_sender,
                       const ConfigurationPtr& configuration,
                       uint16_t target_port) 
: ActiveTest(packet_sender, configuration), target_port_(target_port) {

}

void TCPSynTest::execute_test() {
    random_device rnd;
    target_address_ = resolve_domain("www.example.com");
    sequence_number_ = static_cast<uint32_t>(rnd());
    cout << log_prefix() << "Resolved target address to " << target_address_ << endl;

    auto packet = IP(target_address_) / TCP(target_port_, configuration().source_port());
    TCP& tcp = packet.rfind_pdu<TCP>();
    tcp.seq(sequence_number_);
    tcp.flags(TCP::SYN);
    send_packet(packet);
}

void TCPSynTest::validate_packet(const PDU& pdu) {
    const TCP& tcp = pdu.rfind_pdu<TCP>();
    if (tcp.flags() != (TCP::SYN | TCP::ACK) && tcp.flags() != TCP::RST) {
        throw TestFailed("Invalid flags received");
    }
}

bool TCPSynTest::test_matches_packet(const PDU& pdu) const {
    if (pdu.rfind_pdu<IP>().src_addr() != target_address_) {
        return false;
    }
    const TCP& tcp = pdu.rfind_pdu<TCP>();
    if (tcp.sport() != target_port_) {
        return false;
    }
    return tcp.ack_seq() == sequence_number_ + 1;

}

// Layer 3

Layer3TCPSynTest::Layer3TCPSynTest(const PacketSenderPtr& packet_sender,
                                   const ConfigurationPtr& configuration) 
: TCPSynTest(packet_sender, configuration, 80) {
    disable_on_platform(Configuration::WINDOWS);
}

string Layer3TCPSynTest::name() const {
    return "tcp_layer3_syn_test";
}

void Layer3TCPSynTest::send_packet(PDU& pdu) {
    packet_sender().send(pdu);
}

// Layer 2

Layer2TCPSynTest::Layer2TCPSynTest(const PacketSenderPtr& packet_sender,
                                   const ConfigurationPtr& configuration) 
: TCPSynTest(packet_sender, configuration, 443) {

}

string Layer2TCPSynTest::name() const {
    return "tcp_layer2_syn_test";
}

void Layer2TCPSynTest::send_packet(PDU& pdu) {
    const NetworkInterface& iface = configuration().interface();
    IPv4Address gateway_address = get_gateway_v4_address(iface.name());
    auto gateway_hwaddress = Tins::Utils::resolve_hwaddr(iface, gateway_address,
                                                         packet_sender());
    EthernetII eth = EthernetII(gateway_hwaddress, iface.hw_address()) / pdu;
    eth.rfind_pdu<IP>().src_addr(iface.ipv4_address());
    packet_sender().send(eth);
}

