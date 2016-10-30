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

#include "tcp_ip/stream_follower.h"

#ifdef TINS_HAVE_TCPIP

#include <limits>
#include <algorithm>
#include "memory.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "tcp.h"
#include "ip.h"
#include "ipv6.h"
#include "rawpdu.h"
#include "packet.h"
#include "exceptions.h"
#include "memory_helpers.h"

using std::make_pair;
using std::bind;
using std::pair;
using std::runtime_error;
using std::numeric_limits;
using std::max;
using std::swap;
using std::chrono::system_clock;
using std::chrono::minutes;
using std::chrono::duration_cast;

using Tins::Memory::OutputMemoryStream;
using Tins::Memory::InputMemoryStream;

namespace Tins {
namespace TCPIP {

const size_t StreamFollower::DEFAULT_MAX_BUFFERED_CHUNKS = 512;
const size_t StreamFollower::DEFAULT_MAX_SACKED_INTERVALS = 1024;
const uint32_t StreamFollower::DEFAULT_MAX_BUFFERED_BYTES = 3 * 1024 * 1024; // 3MB
const StreamFollower::timestamp_type StreamFollower::DEFAULT_KEEP_ALIVE = minutes(5);

StreamFollower::StreamFollower() 
: max_buffered_chunks_(DEFAULT_MAX_BUFFERED_CHUNKS),
  max_buffered_bytes_(DEFAULT_MAX_BUFFERED_BYTES), last_cleanup_(0),
  stream_keep_alive_(DEFAULT_KEEP_ALIVE), attach_to_flows_(false) {

}

void StreamFollower::process_packet(PDU& packet) {
    // Use current time
    const system_clock::duration ts = system_clock::now().time_since_epoch();
    process_packet(packet, duration_cast<timestamp_type>(ts));
}

void StreamFollower::process_packet(Packet& packet) {
    process_packet(*packet.pdu(), packet.timestamp());
}

void StreamFollower::process_packet(PDU& packet, const timestamp_type& ts) {
    const TCP* tcp = packet.find_pdu<TCP>();
    if (!tcp) {
        return;
    }
    stream_id identifier = stream_id::make_identifier(packet);
    streams_type::iterator iter = streams_.find(identifier);
    if (iter == streams_.end()) {
        // Start tracking if they're either SYNs or they contain data (attach
        // to an already running flow).
        if (tcp->flags() == TCP::SYN || (attach_to_flows_ && tcp->find_pdu<RawPDU>() != 0)) {
            iter = streams_.insert(make_pair(identifier, Stream(packet, ts))).first;
            iter->second.setup_flows_callbacks();
            if (on_new_connection_) {
                on_new_connection_(iter->second);
            }
            else {
                throw callback_not_set();
            }
            if (tcp->flags() != TCP::SYN) {
                // assume the connection is established
                iter->second.client_flow().state(Flow::ESTABLISHED);
                iter->second.server_flow().state(Flow::ESTABLISHED);
            }
        }
        else {
            // no stream found and no stream was created
            if (last_cleanup_ + stream_keep_alive_ <= ts) {
                cleanup_streams(ts);
            }
            return;
        }
    }
    // We'll process it if we had already seen this stream or if we just attached to
    // it and it contains payload
    Stream& stream = iter->second;
    stream.process_packet(packet, ts);
    // Check for different potential termination
    size_t total_chunks = stream.client_flow().buffered_payload().size() +
                          stream.server_flow().buffered_payload().size();
    uint32_t total_buffered_bytes = stream.client_flow().total_buffered_bytes() +
                                    stream.server_flow().total_buffered_bytes();
    bool terminate_stream = total_chunks > max_buffered_chunks_ ||
                            total_buffered_bytes > max_buffered_bytes_;
    TerminationReason reason = BUFFERED_DATA;
    #ifdef TINS_HAVE_ACK_TRACKER
    if (!terminate_stream) {
        uint32_t count = 0;
        count += stream.client_flow().ack_tracker().acked_intervals().iterative_size();
        count += stream.server_flow().ack_tracker().acked_intervals().iterative_size();
        terminate_stream = count > DEFAULT_MAX_SACKED_INTERVALS;
        reason = SACKED_SEGMENTS;
    }
    #endif // TINS_HAVE_ACK_TRACKER
    if (stream.is_finished() || terminate_stream) {
        // If we're terminating the stream, execute the termination callback
        if (terminate_stream && on_stream_termination_) {
            on_stream_termination_(stream, reason);
        }
        streams_.erase(iter);
    }

    if (last_cleanup_ + stream_keep_alive_ <= ts) {
        cleanup_streams(ts);
    }
}

void StreamFollower::new_stream_callback(const stream_callback_type& callback) {
    on_new_connection_ = callback;
}

void StreamFollower::stream_termination_callback(const stream_termination_callback_type& callback) {
    on_stream_termination_ = callback;
}

Stream& StreamFollower::find_stream(const IPv4Address& client_addr, uint16_t client_port,
                                    const IPv4Address& server_addr, uint16_t server_port) {
    stream_id identifier(stream_id::serialize(client_addr), client_port,
                         stream_id::serialize(server_addr), server_port);
    return find_stream(identifier);
}

Stream& StreamFollower::find_stream(const IPv6Address& client_addr, uint16_t client_port,
                                    const IPv6Address& server_addr, uint16_t server_port) {
    stream_id identifier(stream_id::serialize(client_addr), client_port,
                         stream_id::serialize(server_addr), server_port);
    return find_stream(identifier);
}

Stream& StreamFollower::find_stream(const stream_id& id) {
    streams_type::iterator iter = streams_.find(id);
    if (iter == streams_.end()) {
        throw stream_not_found();
    }
    else {
        return iter->second;
    }
}

void StreamFollower::follow_partial_streams(bool value) {
    attach_to_flows_ = value;
}

void StreamFollower::cleanup_streams(const timestamp_type& now) {
    streams_type::iterator iter = streams_.begin();
    while (iter != streams_.end()) {
        if (iter->second.last_seen() + stream_keep_alive_ <= now) {
            // If we have a termination callback, execute it
            if (on_stream_termination_) {
                on_stream_termination_(iter->second, TIMEOUT);
            }
            streams_.erase(iter++);
        }
        else {
            ++iter;
        }
    }
    last_cleanup_ = now;
}

} // TCPIP
} // Tins

#endif // TINS_HAVE_TCPIP
