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

#include <set>
#include <algorithm>
#include <iostream>
#include <chrono>
#include <stdexcept>
#include "active_test_runner.h"

using std::make_shared;
using std::set;
using std::string;
using std::exception;
using std::cout;
using std::cerr;
using std::endl;
using std::this_thread::sleep_for;
using std::chrono::seconds;

using Tins::PacketSender;

ActiveTestRunner::ActiveTestRunner(const Configuration& configuration) 
: configuration_(make_shared<Configuration>(configuration)),
  packet_sender_(make_shared<PacketSender>()),
  capturer_(*configuration_) {
    packet_sender_->default_interface(configuration.interface());
}

bool ActiveTestRunner::validate_tests() {
    set<string> names;
    for (const auto& test : tests_) {
        if (names.insert(test->name()).second == false) {
            return false;
        }
    }
    return true;
}

void ActiveTestRunner::run() {
    try {
        do_run();
    }
    catch (exception& ex) {
        cerr << "[-] Caught exception while running: " << ex.what() << endl;
    }
}

void ActiveTestRunner::do_run() {
    string prefix = "[runner] ";
    cout << prefix << "Starting capture on interface " << configuration_->interface() << endl;
    capturer_.start_capture();
    cout << prefix << "Executing " << tests_.size() << " tests" << endl;
    for (auto& test : tests_) {
        cout << prefix << "Sending packet for " << test->name() << " test" << endl;
        test->execute();
    }
    cout << prefix << "Done executing tests. Sleeping for a second" << endl;
    sleep_for(seconds(1));
    cout << prefix << "Stopping capture" << endl;
    capturer_.stop_capture();
    cout << prefix << "Capture stopped" << endl;

    auto packets = capturer_.captured_packets();
    cout << prefix << "Captured " << packets.size() << " packets" << endl;
    for (const auto& test : tests_) {
        if (test->is_enabled()) {
            test->validate(packets);
        }
        
    }
}
