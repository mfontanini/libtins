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
#include <functional>
#include <mutex>
#include <condition_variable>
#include "packet_capturer.h"

using std::string;
using std::thread;
using std::move;
using std::bind;
using std::condition_variable;
using std::unique_lock;
using std::lock_guard;
using std::mutex;
using std::ostringstream;

using Tins::PDU;
using Tins::Sniffer;
using Tins::SnifferConfiguration;

PacketCapturer::PacketCapturer(const Configuration& configuration) {

    SnifferConfiguration sniffer_config;
    sniffer_config.set_filter(make_filter(configuration));
    sniffer_config.set_immediate_mode(true);
    sniffer_.reset(new Sniffer(configuration.interface().name(), sniffer_config));
}

void PacketCapturer::start_capture() {
    using std::placeholders::_1;

    mutex mtx;
    condition_variable cond;
    bool started = false;

    running_ = true;
    sniffer_thread_ = thread([&]() {
        {
            lock_guard<mutex> _(mtx);
            started = true;
            cond.notify_one();
        }
        sniffer_->sniff_loop(bind(&PacketCapturer::callback, this, _1));
    });

    unique_lock<mutex> locker(mtx);
    while (!started) {
        cond.wait(locker);
    }
}

void PacketCapturer::stop_capture() {
    running_ = false;
    sniffer_->stop_sniff();
    sniffer_thread_.join();
}

PacketCapturer::PacketStorage PacketCapturer::captured_packets() {
    return move(storage_);
}

bool PacketCapturer::callback(const PDU& pdu) {
    storage_.emplace_back(pdu.clone());
    return running_;
}

string PacketCapturer::make_filter(const Configuration& configuration) const {
    ostringstream oss;
    oss << "((tcp or udp) and (port " << configuration.source_port() 
        << " or port " << configuration.destination_port() << ")) or icmp"
        // Fragmentted IP packets
        << " or (ip[6:2] & 0x1fff) > 0"
        << " or arp";
    return oss.str();
}

