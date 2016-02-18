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
: seq_number_(sequence_number), dest_port_(dest_port) {
    OutputMemoryStream output(dest_address_.data(), dest_address_.size());
    output.write(dest_address);
    flags_.is_v6 = false;
    initialize();
}

Flow::Flow(const IPv6Address& dest_address, uint16_t dest_port,
           uint32_t sequence_number) 
: seq_number_(sequence_number), dest_port_(dest_port) {
    OutputMemoryStream output(dest_address_.data(), dest_address_.size());
    output.write(dest_address);
    flags_.is_v6 = true;
    initialize();
}

void Flow::initialize() {
    total_buffered_bytes_ = 0;
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
        #ifdef HAVE_ACK_TRACKER
        if (flags_.ack_tracking) {
            ack_tracker_.process_packet(*tcp);
        }
        #endif // HAVE_ACK_TRACKER
    }
    if (flags_.ignore_data_packets) {
        return;
    }
    if (!tcp || !raw) {
        return;
    }
    const uint32_t chunk_end = tcp->seq() + raw->payload_size();
    // If the end of the chunk ends after our current sequence number, process it.
    if (seq_compare(chunk_end, seq_number_) >= 0) {
        bool added_some = false;
        uint32_t seq = tcp->seq();
        // If we're going to buffer this and we have a buffering callback, execute it
        if (seq > seq_number_ && on_out_of_order_callback_) {
            on_out_of_order_callback_(*this, seq, raw->payload());
        }

        // If it starts before our sequence number, slice it
        if (seq_compare(seq, seq_number_) < 0) {
            const uint32_t diff = seq_number_ - seq;
            raw->payload().erase(
                raw->payload().begin(),
                raw->payload().begin() + diff
            );
            seq = seq_number_;
        }
        // Store this payload
        store_payload(seq, move(raw->payload()));
        // Keep looping while the fragments seq is lower or equal to our seq
        buffered_payload_type::iterator iter = buffered_payload_.find(seq_number_);
        while (iter != buffered_payload_.end() && seq_compare(iter->first, seq_number_) <= 0) {
            // Does this fragment start before our sequence number?
            if (seq_compare(iter->first, seq_number_) < 0) {
                uint32_t fragment_end = iter->first + iter->second.size();
                int comparison = seq_compare(fragment_end, seq_number_);
                // Does it end after our sequence number? 
                if (comparison > 0) {
                    // Then slice it
                    payload_type& payload = iter->second;
                    // First update this counter
                    total_buffered_bytes_ -= payload.size();
                    payload.erase(
                        payload.begin(),
                        payload.begin() + (seq_number_ - iter->first)
                    );
                    store_payload(seq_number_, move(iter->second));
                    iter = erase_iterator(iter);
                }
                else {
                    // Otherwise, we've seen this part of the payload. Erase it.
                    iter = erase_iterator(iter);
                }
            }
            else {
                // They're equal. Add this payload.
                payload_.insert(
                    payload_.end(),
                    iter->second.begin(), 
                    iter->second.end()
                );
                seq_number_ += iter->second.size();
                iter = erase_iterator(iter);
                added_some = true;
            }
        }
        if (added_some) {
            if (on_data_callback_) {
                on_data_callback_(*this);
            }
        }
    }
    else if (on_out_of_order_callback_) {
        on_out_of_order_callback_(*this, tcp->seq(), raw->payload());
    }
}

void Flow::store_payload(uint32_t seq, payload_type payload) {
    buffered_payload_type::iterator iter = buffered_payload_.find(seq);
    // New segment, store it
    if (iter == buffered_payload_.end()) {
        total_buffered_bytes_ += payload.size();
        buffered_payload_.insert(make_pair(seq, move(payload)));
    }
    else if (iter->second.size() < payload.size()) {
        // Increment by the diff between sizes
        total_buffered_bytes_ += (payload.size() - iter->second.size());
        // If we already have payload on this position but it's a shorter
        // chunk than the new one, replace it
        iter->second = move(payload);
    }
}

Flow::buffered_payload_type::iterator Flow::erase_iterator(buffered_payload_type::iterator iter) {
    buffered_payload_type::iterator output = iter;
    total_buffered_bytes_ -= iter->second.size();
    ++output;
    buffered_payload_.erase(iter);
    if (output == buffered_payload_.end()) {
        output = buffered_payload_.begin();
    }
    return output;
}

void Flow::update_state(const TCP& tcp) {
    if ((tcp.flags() & TCP::FIN) != 0) {
        state_ = FIN_SENT;
    }
    else if ((tcp.flags() & TCP::RST) != 0) {
        state_ = RST_SENT;
    }
    else if (state_ == SYN_SENT && (tcp.flags() & TCP::ACK) != 0) {
        #ifdef HAVE_ACK_TRACKER
            ack_tracker_ = AckTracker(tcp.ack_seq());
        #endif // HAVE_ACK_TRACKER
        state_ = ESTABLISHED;
        seq_number_++;
    }
    else if (state_ == UNKNOWN && (tcp.flags() & TCP::SYN) != 0) {
        // This is the server's state, sending it's first SYN|ACK
        #ifdef HAVE_ACK_TRACKER
            ack_tracker_ = AckTracker(tcp.ack_seq());
        #endif // HAVE_ACK_TRACKER
        state_ = SYN_SENT;
        seq_number_ = tcp.seq();
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
    return payload_;
}

Flow::State Flow::state() const {
    return state_;
}

uint32_t Flow::sequence_number() const {
    return seq_number_;
}

const Flow::buffered_payload_type& Flow::buffered_payload() const {
    return buffered_payload_;
}

Flow::buffered_payload_type& Flow::buffered_payload() {
    return buffered_payload_;
}

uint32_t Flow::total_buffered_bytes() const {
    return total_buffered_bytes_;
}

Flow::payload_type& Flow::payload() {
    return payload_;
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
    #ifdef HAVE_ACK_TRACKER
    flags_.ack_tracking = 1;
    #else
    throw feature_disabled();
    #endif
}

bool Flow::ack_tracking_enabled() const {
    return flags_.ack_tracking;
}

#ifdef HAVE_ACK_TRACKER
const AckTracker& Flow::ack_tracker() const {
    return ack_tracker_;
}

AckTracker& Flow::ack_tracker() {
    return ack_tracker_;
}

#endif // HAVE_ACK_TRACKER

} // TCPIP
} // Tins

#endif // TINS_IS_CXX11
