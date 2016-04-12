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

#ifndef TINS_ACTIVE_TCP_TESTS_H
#define TINS_ACTIVE_TCP_TESTS_H

#include <cstdint>
#include "active_test.h"
#include "tins/ip_address.h"

class TCPSynTest : public ActiveTest {
public:
    TCPSynTest(const PacketSenderPtr& packet_sender,
               const ConfigurationPtr& configuration,
               uint16_t target_port);
private:
    void execute_test();
    void validate_packet(const Tins::PDU& pdu);
    bool test_matches_packet(const Tins::PDU& pdu) const;
    virtual void send_packet(Tins::PDU& pdu) = 0;

    Tins::IPv4Address target_address_;
    uint32_t sequence_number_;
    uint16_t target_port_;
};

// Sends a SYN using IP as the lowest layer
class Layer3TCPSynTest : public TCPSynTest {
public:
    Layer3TCPSynTest(const PacketSenderPtr& packet_sender,
                     const ConfigurationPtr& configuration);

    std::string name() const;
private:
    void send_packet(Tins::PDU& pdu);
};

// Sends a SYN using Ethernet as the lowest layer
class Layer2TCPSynTest : public TCPSynTest {
public:
    Layer2TCPSynTest(const PacketSenderPtr& packet_sender,
                     const ConfigurationPtr& configuration);

    std::string name() const;
private:
    void send_packet(Tins::PDU& pdu);
};


#endif // TINS_ACTIVE_TCP_TESTS_H
