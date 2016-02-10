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

#if TINS_IS_CXX11

#include <limits>
#include <algorithm>
#include "memory.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "tcp.h"
#include "ip.h"
#include "ipv6.h"
#include "rawpdu.h"
#include "exceptions.h"
#include "memory_helpers.h"

using std::make_pair;
using std::bind;
using std::pair;
using std::runtime_error;
using std::numeric_limits;
using std::max;
using std::swap;

using Tins::Memory::OutputMemoryStream;
using Tins::Memory::InputMemoryStream;

namespace Tins {
namespace TCPIP {

const size_t StreamFollower::DEFAULT_MAX_BUFFERED_CHUNKS = 512;

StreamFollower::StreamFollower() 
: max_buffered_chunks_(DEFAULT_MAX_BUFFERED_CHUNKS), attach_to_flows_(false) {

}

bool StreamFollower::process_packet(PDU& packet) {
    stream_id identifier = make_stream_id(packet);
    streams_type::iterator iter = streams_.find(identifier);
    bool process = true;
    if (iter == streams_.end()) {
        const TCP& tcp = packet.rfind_pdu<TCP>();
        // Start tracking if they're either SYNs or they contain data (attach
        // to an already running flow).
        if (tcp.flags() == TCP::SYN || (attach_to_flows_ && tcp.find_pdu<RawPDU>() != 0)) {
            iter = streams_.insert(make_pair(identifier, Stream(packet))).first;
            iter->second.setup_flows_callbacks();
            if (on_new_connection_) {
                on_new_connection_(iter->second);
            }
            else {
                // TODO: use proper exception
                throw runtime_error("No new connection callback set");
            }
            if (tcp.flags() == TCP::SYN) {
                process = false;
            }
            else {
                // Otherwise, assume the connection is established
                iter->second.client_flow().state(Flow::ESTABLISHED);
                iter->second.server_flow().state(Flow::ESTABLISHED);
            }
        }
        else {
            process = false;
        }
    }
    // We'll process it if we had already seen this stream or if we just attached to
    // it and it contains payload
    if (process) {
        Stream& stream = iter->second;
        stream.process_packet(packet);
        size_t total_chunks = stream.client_flow().buffered_payload().size() + 
                              stream.server_flow().buffered_payload().size();
        if (stream.is_finished() || total_chunks > max_buffered_chunks_) {
            streams_.erase(iter);
        }
    }
    return true;
}

void StreamFollower::new_stream_callback(const stream_callback_type& callback) {
    on_new_connection_ = callback;
}

Stream& StreamFollower::find_stream(IPv4Address client_addr, uint16_t client_port,
                                    IPv4Address server_addr, uint16_t server_port) {
    stream_id identifier(serialize(client_addr), client_port,
                         serialize(server_addr), server_port);
    return find_stream(identifier);
}

Stream& StreamFollower::find_stream(IPv6Address client_addr, uint16_t client_port,
                                    IPv6Address server_addr, uint16_t server_port) {
    stream_id identifier(serialize(client_addr), client_port,
                         serialize(server_addr), server_port);
    return find_stream(identifier);
}

StreamFollower::stream_id StreamFollower::make_stream_id(const PDU& packet) {
    const TCP* tcp = packet.find_pdu<TCP>();
    if (!tcp) {
        // TODO: define proper exception
        throw runtime_error("No TCP");
    }
    if (const IP* ip = packet.find_pdu<IP>()) {
        return stream_id(serialize(ip->src_addr()), tcp->sport(),
                         serialize(ip->dst_addr()), tcp->dport());
    }
    else if (const IPv6* ip = packet.find_pdu<IPv6>()) {
        return stream_id(serialize(ip->src_addr()), tcp->sport(),
                         serialize(ip->dst_addr()), tcp->dport());
    }
    else {
        // TODO: define proper exception
        throw runtime_error("No layer 3");
    }
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

StreamFollower::address_type StreamFollower::serialize(IPv4Address address) {
    address_type addr;
    OutputMemoryStream output(addr.data(), addr.size());
    addr.fill(0);
    output.write(address);
    return addr; 
}

StreamFollower::address_type StreamFollower::serialize(const IPv6Address& address) {
    address_type addr;
    OutputMemoryStream output(addr.data(), addr.size());
    addr.fill(0);
    output.write(address);
    return addr;
}

// stream_id

StreamFollower::stream_id::stream_id(const address_type& client_addr,
                                     uint16_t client_port,
                                     const address_type& server_addr,
                                     uint16_t server_port) 
: min_address(client_addr), max_address(server_addr), min_address_port(client_port),
  max_address_port(server_port) {
    if (min_address > max_address) {
        swap(min_address, max_address);
        swap(min_address_port, max_address_port);
    }
    else if (min_address == max_address && min_address_port > max_address_port) {
        // If the address is the same, just sort ports
        swap(min_address_port, max_address_port);
    }
}

bool StreamFollower::stream_id::operator<(const stream_id& rhs) const {
    return tie(min_address, min_address_port, max_address, max_address_port) <
        tie(rhs.min_address, rhs.min_address_port, rhs.max_address, rhs.max_address_port);
}

} // TCPIP
} // Tins

#endif // TINS_IS_CXX11
