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

#ifndef TINS_ACTIVE_TEST_H
#define TINS_ACTIVE_TEST_H

#include <memory>
#include <stdexcept>
#include "tins/packet_sender.h"
#include "configuration.h"
#include "packet_capturer.h"

namespace Tins {

class PDU;

} // Tins

class TestFailed : public std::runtime_error {
public:
    TestFailed(const std::string& message) : std::runtime_error(message) {

    }
};

class ActiveTest {
public:
    using PacketSenderPtr = std::shared_ptr<Tins::PacketSender>;
    using ConfigurationPtr = std::shared_ptr<Configuration>;

    ActiveTest(const PacketSenderPtr& packet_sender,
               const ConfigurationPtr& configuration);

    virtual ~ActiveTest() = default;

    void execute();
    std::string log_prefix() const;
    bool matches_packet(const Tins::PDU& pdu) const;
    bool is_enabled() const;
    void validate(PacketCapturer::PacketStorage& packets);
    virtual std::string name() const = 0;
protected:
    Tins::PacketSender& packet_sender();
    const Tins::PacketSender& packet_sender() const;
    Configuration& configuration();
    const Configuration& configuration() const;
    virtual bool test_matches_packet(const Tins::PDU& pdu) const = 0;
    virtual void execute_test() = 0;
    virtual void validate_packet(const Tins::PDU& pdu) = 0;
    void disable_on_platform(Configuration::Platform platform);
private:
    PacketSenderPtr packet_sender_;
    ConfigurationPtr configuration_;
    unsigned disabled_platforms_ = 0;
};

#endif // TINS_ACTIVE_TEST_H
