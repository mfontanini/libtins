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

#ifndef TINS_PACKET_CAPTURER_H
#define TINS_PACKET_CAPTURER_H

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <vector>
#include "tins/sniffer.h"
#include "configuration.h"

class PacketCapturer {
public:
    using PacketPtr = std::unique_ptr<Tins::PDU>;
    using PacketStorage = std::vector<PacketPtr>;

    PacketCapturer(const Configuration& configuration);

    void start_capture();
    void stop_capture();

    PacketStorage captured_packets();
private:
    bool callback(const Tins::PDU& pdu);
    std::string make_filter(const Configuration& configuration) const;

    std::unique_ptr<Tins::Sniffer> sniffer_;
    std::thread sniffer_thread_;
    PacketStorage storage_;
    std::atomic<bool> running_;
};

#endif // TINS_PACKET_CAPTURER_H
