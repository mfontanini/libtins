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

#include <limits>
#include <algorithm>
#include "tcp_ip.h"
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
using std::runtime_error;
using std::numeric_limits;
using std::max;
using std::swap;

using Tins::Memory::OutputMemoryStream;
using Tins::Memory::InputMemoryStream;

namespace Tins {
namespace TCPIP {

// As defined by RFC 1982 - 2 ^ (SERIAL_BITS - 1)
static const uint32_t seq_number_diff = 2147483648U;

// Compares sequence numbers as defined by RFC 1982.
int seq_compare(uint32_t seq1, uint32_t seq2) {
    if (seq1 == seq2) {
        return 0;
    }
    if (seq1 < seq2) {
        return (seq2 - seq1 < seq_number_diff) ? -1 : 1;
    }
    else {
        return (seq1 - seq2 > seq_number_diff) ? -1 : 1;
    }
}

// TCPFlow

TCPFlow::TCPFlow(const IPv4Address& dest_address, uint16_t dest_port,
                 uint32_t sequence_number) 
: seq_number_(sequence_number), dest_port_(dest_port), is_v6_(false),
  state_(UNKNOWN) {
    OutputMemoryStream output(dest_address_.data(), dest_address_.size());
    output.write(dest_address);
}

TCPFlow::TCPFlow(const IPv6Address& dest_address, uint16_t dest_port,
                 uint32_t sequence_number) 
: seq_number_(sequence_number), dest_port_(dest_port), is_v6_(true),
  state_(UNKNOWN) {
    OutputMemoryStream output(dest_address_.data(), dest_address_.size());
    output.write(dest_address);
}

void TCPFlow::data_callback(const event_callback& callback) {
    on_data_callback_ = callback;
}

void TCPFlow::buffering_callback(const event_callback& callback) {
    on_buffering_callback_= callback;
}

void TCPFlow::process_packet(PDU& pdu) {
    TCP* tcp = pdu.find_pdu<TCP>();
    RawPDU* raw = pdu.find_pdu<RawPDU>(); 
    // If we sent a packet with RST or FIN on, this flow is done
    if (tcp) {
        update_state(*tcp);
    }
    if (!tcp || !raw) {
        return;
    }
    const uint32_t chunk_end = tcp->seq() + raw->payload_size();
    // If the end of the chunk ends after our current sequence number, process it.
    if (seq_compare(chunk_end, seq_number_) >= 0) {
        bool added_some = false;
        uint32_t seq = tcp->seq();
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
        store_payload(seq, raw->payload());
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
                    payload.erase(
                        payload.begin(),
                        payload.begin() + (seq_number_ - iter->first)
                    );
                    store_payload(seq_number_, iter->second);
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
                // If we don't have any other payload, we're done
                if (buffered_payload_.empty()) {
                    break;
                }
            }
        }
        if (added_some) {
            if (on_data_callback_) {
                on_data_callback_(*this);
            }
        }
        else {
            if (on_buffering_callback_) {
                on_buffering_callback_(*this);
            }
        }
    }
}

void TCPFlow::store_payload(uint32_t seq, const payload_type& payload) {
    buffered_payload_type::iterator iter = buffered_payload_.find(seq);
    // New segment, store it
    if (iter == buffered_payload_.end()) {
        buffered_payload_.insert(make_pair(seq, payload));
    }
    else if (iter->second.size() < payload.size()) {
        // If we already have payload on this position but it's a shorter
        // chunk than the new one, replace it
        iter->second = payload;
    }
}

TCPFlow::buffered_payload_type::iterator TCPFlow::erase_iterator(buffered_payload_type::iterator iter) {
    buffered_payload_type::iterator output = iter;
    ++output;
    buffered_payload_.erase(iter);
    if (output == buffered_payload_.end()) {
        output = buffered_payload_.begin();
    }
    return output;
}

void TCPFlow::update_state(const TCP& tcp) {
    if ((tcp.flags() & TCP::FIN) != 0) {
        state_ = FIN_SENT;
    }
    else if ((tcp.flags() & TCP::RST) != 0) {
        state_ = RST_SENT;
    }
    else if (state_ == SYN_SENT && (tcp.flags() & TCP::ACK) != 0) {
        state_ = ESTABLISHED;
        seq_number_++;
    }
    else if (state_ == UNKNOWN && (tcp.flags() & TCP::SYN) != 0) {
        state_ = SYN_SENT;
        seq_number_ = tcp.seq();
    }
}

bool TCPFlow::is_v6() const {
    return is_v6_;
}

bool TCPFlow::is_finished() const {
    return state_ == FIN_SENT || state_ == RST_SENT;
}

bool TCPFlow::packet_belongs(const PDU& packet) const {
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

IPv4Address TCPFlow::dst_addr_v4() const {
    InputMemoryStream stream(dest_address_.data(), dest_address_.size());
    return stream.read<IPv4Address>();
}

IPv6Address TCPFlow::dst_addr_v6() const {
    InputMemoryStream stream(dest_address_.data(), dest_address_.size());
    return stream.read<IPv6Address>();
}

uint16_t TCPFlow::dport() const {
    return dest_port_;
}

const TCPFlow::payload_type& TCPFlow::payload() const {
    return payload_;
}

TCPFlow::payload_type& TCPFlow::payload() {
    return payload_;
}

void TCPFlow::state(State new_state) {
    state_ = new_state;
}

TCPFlow::State TCPFlow::state() const {
    return state_;
}

uint32_t TCPFlow::sequence_number() const {
    return seq_number_;
}

// TCPStream

TCPStream::TCPStream(const PDU& packet) 
: client_flow_(extract_client_flow(packet)), 
server_flow_(extract_server_flow(packet)) {

}

TCPStream::TCPStream(const TCPFlow& client_flow, const TCPFlow& server_flow) 
: client_flow_(client_flow), server_flow_(server_flow) {

}

void TCPStream::process_packet(PDU& packet) {
    if (client_flow_.packet_belongs(packet)) {
        client_flow_.process_packet(packet);
    }
    else if (server_flow_.packet_belongs(packet)) {
        server_flow_.process_packet(packet);
    }
}

TCPFlow& TCPStream::client_flow() {
    return client_flow_;
}

const TCPFlow& TCPStream::client_flow() const {
    return client_flow_;
}

TCPFlow& TCPStream::server_flow() {
    return server_flow_;
}

const TCPFlow& TCPStream::server_flow() const {
    return server_flow_;
}

void TCPStream::client_data_callback(const stream_callback& callback) {
    on_client_data_callback_ = callback;
}

void TCPStream::server_data_callback(const stream_callback& callback) {
    on_server_data_callback_ = callback;
}

void TCPStream::client_buffering_callback(const stream_callback& callback) {
    on_client_buffering_callback_ = callback;
}

void TCPStream::server_buffering_callback(const stream_callback& callback) {
    on_server_buffering_callback_ = callback;
}

TCPFlow TCPStream::extract_client_flow(const PDU& packet) {
    const TCP* tcp = packet.find_pdu<TCP>();
    if (!tcp) {
        // TODO: define proper exception
        throw runtime_error("No TCP");
    }
    if (const IP* ip = packet.find_pdu<IP>()) {
        return TCPFlow(ip->dst_addr(), tcp->dport(), tcp->seq());
    }
    else if (const IPv6* ip = packet.find_pdu<IPv6>()) {
        return TCPFlow(ip->dst_addr(), tcp->dport(), tcp->seq());
    }
    else {
        // TODO: define proper exception
        throw runtime_error("No valid layer 3");
    }
}

TCPFlow TCPStream::extract_server_flow(const PDU& packet) {
    const TCP* tcp = packet.find_pdu<TCP>();
    if (!tcp) {
        // TODO: define proper exception
        throw runtime_error("No TCP");
    }
    if (const IP* ip = packet.find_pdu<IP>()) {
        return TCPFlow(ip->src_addr(), tcp->sport(), tcp->ack_seq());
    }
    else if (const IPv6* ip = packet.find_pdu<IPv6>()) {
        return TCPFlow(ip->src_addr(), tcp->sport(), tcp->ack_seq());
    }
    else {
        // TODO: define proper exception
        throw runtime_error("No valid layer 3");
    }
}

void TCPStream::setup_flows_callbacks() {
    using std::placeholders::_1;
    client_flow_.data_callback(bind(&TCPStream::on_client_flow_data, this, _1));
    server_flow_.data_callback(bind(&TCPStream::on_server_flow_data, this, _1));
    client_flow_.buffering_callback(bind(&TCPStream::on_client_buffering, this, _1));
    server_flow_.buffering_callback(bind(&TCPStream::on_server_buffering, this, _1));
}

void TCPStream::on_client_flow_data(const TCPFlow& flow) {
    if (on_client_data_callback_) {
        on_client_data_callback_(*this);
    }
}

void TCPStream::on_server_flow_data(const TCPFlow& flow) {
    if (on_server_data_callback_) {
        on_server_data_callback_(*this);
    }
}

void TCPStream::on_client_buffering(const TCPFlow& flow) {
    if (on_client_buffering_callback_) {
        on_client_buffering_callback_(*this);
    }
}

void TCPStream::on_server_buffering(const TCPFlow& flow) {
    if (on_server_buffering_callback_) {
        on_server_buffering_callback_(*this);
    }
}

// TCPStreamFollower

TCPStreamFollower::TCPStreamFollower() 
: attach_to_flows_(false) {

}

void TCPStreamFollower::process_packet(PDU& packet) {
    stream_id identifier = make_stream_id(packet);
    streams_type::iterator iter = streams_.find(identifier);
    bool process = true;
    if (iter == streams_.end()) {
        const TCP& tcp = packet.rfind_pdu<TCP>();
        // Start tracking if they're either SYNs or they contain data (attach
        // to an already running flow).
        if (tcp.flags() == TCP::SYN || (attach_to_flows_ && tcp.find_pdu<RawPDU>() != 0)) {
            iter = streams_.insert(make_pair(identifier, make_stream(packet))).first;
            iter->second.setup_flows_callbacks();
            if (tcp.flags() == TCP::SYN) {
                // If it's a SYN, set the proper state
                iter->second.client_flow().state(TCPFlow::SYN_SENT);
                process = false;
            }
            else {
                // Otherwise, assume the connection is established
                iter->second.client_flow().state(TCPFlow::ESTABLISHED);
                iter->second.server_flow().state(TCPFlow::ESTABLISHED);
            }
        }
        else {
            process = false;
        }
    }
    // We'll process it if we had already seen this stream or if we just attached to
    // it and it contains payload
    if (process) {
        iter->second.process_packet(packet);
    }
}

void TCPStreamFollower::client_data_callback(const stream_callback& callback) {
    on_client_data_callback_ = callback;
}

void TCPStreamFollower::server_data_callback(const stream_callback& callback) {
    on_server_data_callback_ = callback;
}

void TCPStreamFollower::client_buffering_callback(const stream_callback& callback) {
    on_client_buffering_callback_ = callback;
}

void TCPStreamFollower::server_buffering_callback(const stream_callback& callback) {
    on_server_buffering_callback_ = callback;
}

TCPStream& TCPStreamFollower::find_stream(IPv4Address client_addr, uint16_t client_port,
                                          IPv4Address server_addr, uint16_t server_port) {
    stream_id identifier(serialize(client_addr), client_port,
                         serialize(server_addr), server_port);
    streams_type::iterator iter = streams_.find(identifier);
    if (iter == streams_.end()) {
        // TODO: define proper exception
        throw runtime_error("Stream not found");
    }
    else {
        return iter->second;
    }
}

TCPStreamFollower::stream_id TCPStreamFollower::make_stream_id(const PDU& packet) {
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

TCPStream TCPStreamFollower::make_stream(const PDU& packet) {
    TCPStream stream(packet);
    stream.client_data_callback(on_client_data_callback_);
    stream.server_data_callback(on_server_data_callback_);
    stream.client_buffering_callback(on_client_buffering_callback_);
    stream.server_buffering_callback(on_server_buffering_callback_);
    return stream;
}

TCPStreamFollower::address_type TCPStreamFollower::serialize(IPv4Address address) {
    address_type addr;
    OutputMemoryStream output(addr.data(), addr.size());
    output.write(address);
    return addr; 
}

TCPStreamFollower::address_type TCPStreamFollower::serialize(const IPv6Address& address) {
    address_type addr;
    OutputMemoryStream output(addr.data(), addr.size());
    output.write(address);
    return addr;
}

// stream_id

TCPStreamFollower::stream_id::stream_id(const address_type& client_addr,
                                        uint16_t client_port,
                                        const address_type& server_addr,
                                        uint16_t server_port) 
: min_address(client_addr), max_address(server_addr), min_address_port(client_port),
max_address_port(server_port) {
    if (min_address > max_address) {
        swap(min_address, max_address);
        swap(min_address_port, max_address_port);
    }
}

bool TCPStreamFollower::stream_id::operator<(const stream_id& rhs) const {
    return tie(min_address, min_address_port, max_address, max_address_port) <
        tie(rhs.min_address, rhs.min_address_port, rhs.max_address, rhs.max_address_port);
}

} // TCPIP
} // Tins
