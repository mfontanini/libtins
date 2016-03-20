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

#ifndef TINS_ACTIVE_TEST_RUNNER_H
#define TINS_ACTIVE_TEST_RUNNER_H

#include <vector>
#include <memory>
#include "active_test.h"
#include "configuration.h"
#include "packet_capturer.h"

class ActiveTestRunner {
public:
    ActiveTestRunner(const Configuration& configuration);

    template <typename T>
    void add_test();

    bool validate_tests();
    void run();
private:
    using ConfigurationPtr = ActiveTest::ConfigurationPtr;
    using ActiveTestPtr = std::unique_ptr<ActiveTest>;

    template <typename... EmptyTail>
    void add_tests() { }

    void do_run();

    ConfigurationPtr configuration_;
    ActiveTest::PacketSenderPtr packet_sender_;
    PacketCapturer capturer_;
    std::vector<ActiveTestPtr> tests_;
};

template <typename T>
void ActiveTestRunner::add_test() {
    tests_.emplace_back(new T(packet_sender_, configuration_));
}

#endif // TINS_ACTIVE_TEST_RUNNER_H
