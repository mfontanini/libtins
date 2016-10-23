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

#include "tcp_ip/flow.h"

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
#include "internals.h"
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
using Tins::Internals::seq_compare;

namespace Tins {
namespace TCPIP {

Flow::Flow(const IPv4Address& dest_address, uint16_t dest_port,
           uint32_t sequence_number) 
: data_tracker_(sequence_number), dest_port_(dest_port) {
    OutputMemoryStream output(dest_address_.data(), dest_address_.size());
    output.write(dest_address);
    flags_.is_v6 = false;
    initialize();
}

Flow::Flow(const IPv6Address& dest_address, uint16_t dest_port,
           uint32_t sequence_number) 
: data_tracker_(sequence_number), dest_port_(dest_port) {
    OutputMemoryStream output(dest_address_.data(), dest_address_.size());
    output.write(dest_address);
    flags_.is_v6 = true;
    initialize();
}

void Flow::initialize() {
    state_ = UNKNOWN;
    mss_ = -1;
}

void Flow::data_callback(const data_available_callback_type& callback) {
    on_data_callback_ = callback;
}

void Flow::out_of_order_callback(const flow_packet_callback_type& callback) {
    on_out_of_order_callback_ = callback;
}

void Flow::process_packet(PDU& pdu) {
    TCP* tcp = pdu.find_pdu<TCP>();
    RawPDU* raw = pdu.find_pdu<RawPDU>(); 
    // Update the internal state first
    if (tcp) {
        update_state(*tcp);
        #ifdef TINS_HAVE_ACK_TRACKER
        if (flags_.ack_tracking) {
            ack_tracker_.process_packet(*tcp);
        }
        #endif // TINS_HAVE_ACK_TRACKER
    }
    if (flags_.ignore_data_packets) {
        return;
    }
    if (!tcp || !raw) {
        return;
    }
    const uint32_t chunk_end = tcp->seq() + raw->payload_size();
    const uint32_t current_seq = data_tracker_.sequence_number();
    // If the end of the chunk ends before the current sequence number or
    // if we're going to buffer this and we have a buffering callback, execute it
    if (seq_compare(chunk_end, current_seq) < 0 ||
            seq_compare(tcp->seq(), current_seq) > 0){
        if (on_out_of_order_callback_) {
            on_out_of_order_callback_(*this, tcp->seq(), raw->payload());
        }
    }

    // can process either way, since it will abort immediately if not needed
    if (data_tracker_.process_payload(tcp->seq(), move(raw->payload()))) {
        if (on_data_callback_) {
            on_data_callback_(*this);
        }
    }
}

void Flow::advance_sequence(uint32_t seq) {
    data_tracker_.advance_sequence(seq);
}

void Flow::update_state(const TCP& tcp) {
    if ((tcp.flags() & TCP::FIN) != 0) {
        state_ = FIN_SENT;
    }
    else if ((tcp.flags() & TCP::RST) != 0) {
        state_ = RST_SENT;
    }
    else if (state_ == SYN_SENT && (tcp.flags() & TCP::ACK) != 0) {
        #ifdef TINS_HAVE_ACK_TRACKER
            ack_tracker_ = AckTracker(tcp.ack_seq());
        #endif // TINS_HAVE_ACK_TRACKER
        state_ = ESTABLISHED;
    }
    else if (state_ == UNKNOWN && (tcp.flags() & TCP::SYN) != 0) {
        // This is the server's state, sending it's first SYN|ACK
        #ifdef TINS_HAVE_ACK_TRACKER
            ack_tracker_ = AckTracker(tcp.ack_seq());
        #endif // TINS_HAVE_ACK_TRACKER
        state_ = SYN_SENT;
        data_tracker_.sequence_number(tcp.seq() + 1);
        const TCP::option* mss_option = tcp.search_option(TCP::MSS);
        if (mss_option) {
            mss_ = mss_option->to<uint16_t>();
        }
        flags_.sack_permitted = tcp.has_sack_permitted();
    }
}

bool Flow::is_v6() const {
    return flags_.is_v6;
}

bool Flow::is_finished() const {
    return state_ == FIN_SENT || state_ == RST_SENT;
}

bool Flow::packet_belongs(const PDU& packet) const {
    if (is_v6()) {
        const IPv6* ip = packet.find_pdu<IPv6>();
        if (!ip || ip->dst_addr() != dst_addr_v6()) {
            return false;
        }
    }
    else {
        const IP* ip = packet.find_pdu<IP>();
        if (!ip || ip->dst_addr() != dst_addr_v4()) {
            return false;
        }
    }
    const TCP* tcp = packet.find_pdu<TCP>();
    return tcp && tcp->dport() == dport();
}

IPv4Address Flow::dst_addr_v4() const {
    InputMemoryStream stream(dest_address_.data(), dest_address_.size());
    return stream.read<IPv4Address>();
}

IPv6Address Flow::dst_addr_v6() const {
    InputMemoryStream stream(dest_address_.data(), dest_address_.size());
    return stream.read<IPv6Address>();
}

uint16_t Flow::dport() const {
    return dest_port_;
}

const Flow::payload_type& Flow::payload() const {
    return data_tracker_.payload();
}

Flow::State Flow::state() const {
    return state_;
}

uint32_t Flow::sequence_number() const {
    return data_tracker_.sequence_number();
}

const Flow::buffered_payload_type& Flow::buffered_payload() const {
    return data_tracker_.buffered_payload();
}

Flow::buffered_payload_type& Flow::buffered_payload() {
    return data_tracker_.buffered_payload();
}

uint32_t Flow::total_buffered_bytes() const {
    return data_tracker_.total_buffered_bytes();
}

Flow::payload_type& Flow::payload() {
    return data_tracker_.payload();
}

void Flow::state(State new_state) {
    state_ = new_state;
}

void Flow::ignore_data_packets() {
    flags_.ignore_data_packets = true;
}

int Flow::mss() const {
    return mss_;
}

bool Flow::sack_permitted() const {
    return flags_.sack_permitted;
}

void Flow::enable_ack_tracking() {
    #ifdef TINS_HAVE_ACK_TRACKER
    flags_.ack_tracking = 1;
    #else
    throw feature_disabled();
    #endif
}

bool Flow::ack_tracking_enabled() const {
    return flags_.ack_tracking;
}

#ifdef TINS_HAVE_ACK_TRACKER
const AckTracker& Flow::ack_tracker() const {
    return ack_tracker_;
}

AckTracker& Flow::ack_tracker() {
    return ack_tracker_;
}

#endif // TINS_HAVE_ACK_TRACKER

} // TCPIP
} // Tins

#endif // TINS_IS_CXX11
