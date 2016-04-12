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
#include <stdexcept>
#include "configuration.h"
#include "active_test_runner.h"
#include "ipv4_tests.h"
#include "tcp_tests.h"
#include "utils_tests.h"
#include "tins/network_interface.h"

using std::cerr;
using std::endl;
using std::exception;
using std::runtime_error;

using Tins::NetworkInterface;

int main() {
    try {
        Configuration config;
        config.source_port(1234);
        config.destination_port(4321);
        config.interface(NetworkInterface::default_interface());

        ActiveTestRunner runner(config);
        runner.add_test<IPv4SourceAddressTest>();
        runner.add_test<IPv4FragmentationTest>();
        runner.add_test<Layer3TCPSynTest>();
        runner.add_test<Layer2TCPSynTest>();
        runner.add_test<ResolveHWAddressTest>();

        if (!runner.validate_tests()) {
            throw runtime_error("Test validation failed");
        }
        runner.run();
    }
    catch (exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
}