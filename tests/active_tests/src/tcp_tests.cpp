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
#include "tins/utils.h"

using std::string;
using std::cout;
using std::endl;
using std::random_device;

using Tins::PDU;
using Tins::TCP;
using Tins::IP;
using Tins::Utils::resolve_domain;

TCPSynTest::TCPSynTest(const PacketSenderPtr& packet_sender,
                       const ConfigurationPtr& configuration) 
: ActiveTest(packet_sender, configuration) {
    disable_on_platform(Configuration::WINDOWS);
}

string TCPSynTest::name() const {
    return "tcp_syn_test";
}

void TCPSynTest::execute_test() {
    random_device rnd;
    target_address_ = resolve_domain("www.example.com");
    sequence_number_ = static_cast<uint32_t>(rnd());
    cout << log_prefix() << "Resolved target address to " << target_address_ << endl;

    auto packet = IP(target_address_) / TCP(80, configuration()->source_port());
    TCP& tcp = packet.rfind_pdu<TCP>();
    tcp.seq(sequence_number_);
    tcp.flags(TCP::SYN);
    packet_sender()->send(packet);
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
    if (tcp.sport() != 80) {
        return false;
    }
    return tcp.ack_seq() == sequence_number_ + 1;

}
