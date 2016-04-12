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

#include <iostream>
#include "tins/exceptions.h"
#include "tins/pdu.h"
#include "active_test.h"

using std::cout;
using std::endl;
using std::string;

using Tins::PDU;
using Tins::PacketSender;
using Tins::pdu_not_found;
using Tins::option_not_found;

ActiveTest::ActiveTest(const PacketSenderPtr& packet_sender,
                       const ConfigurationPtr& configuration)
: packet_sender_(packet_sender), configuration_(configuration) {

}

void ActiveTest::execute() {
    if (is_enabled()) {
        execute_test();
    }
    else {
        cout << log_prefix() << "not running as test is disabled on this platform" << endl;
    }
}

string ActiveTest::log_prefix() const {
    return "[" + name() + "] ";
}

bool ActiveTest::matches_packet(const PDU& pdu) const {
    try {
        return test_matches_packet(pdu);
    }
    catch (pdu_not_found&) {
        return false;
    }
    catch (option_not_found&) {
        return false;
    }
}

bool ActiveTest::is_enabled() const {
    return (configuration_->current_platform() & disabled_platforms_) == 0;
}

void ActiveTest::validate(PacketCapturer::PacketStorage& packets) {
    string prefix = log_prefix();
    size_t i = 0;
    while (i < packets.size() && !matches_packet(*packets[i])) {
        ++i;
    }
    if (i == packets.size()) {
        cout << prefix << "ERROR: Packet was not captured" << endl;
    }
    else {
        try {
            validate_packet(*packets[i]);
            cout << prefix << "OK" << endl;
        }
        catch (TestFailed& ex) {
            cout << prefix << "ERROR: " << ex.what() << endl;
        }
        packets.erase(packets.begin() + i);
    }
}

PacketSender& ActiveTest::packet_sender() {
    return *packet_sender_;
}

const PacketSender& ActiveTest::packet_sender() const {
    return *packet_sender_;
}

Configuration& ActiveTest::configuration() {
    return *configuration_;
}

const Configuration& ActiveTest::configuration() const {
    return *configuration_;
}

void ActiveTest::disable_on_platform(Configuration::Platform platform) {
    disabled_platforms_ |= static_cast<unsigned>(platform);
}
