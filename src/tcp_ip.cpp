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

#include "tcp_ip.h"

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

// Flow

Flow::Flow(const IPv4Address& dest_address, uint16_t dest_port,
           uint32_t sequence_number) 
: seq_number_(sequence_number), dest_port_(dest_port), state_(UNKNOWN),
  is_v6_(false) {
    OutputMemoryStream output(dest_address_.data(), dest_address_.size());
    output.write(dest_address);
}

Flow::Flow(const IPv6Address& dest_address, uint16_t dest_port,
           uint32_t sequence_number) 
: seq_number_(sequence_number), dest_port_(dest_port), state_(UNKNOWN),
  is_v6_(true) {
    OutputMemoryStream output(dest_address_.data(), dest_address_.size());
    output.write(dest_address);
}

void Flow::data_callback(const event_callback& callback) {
    on_data_callback_ = callback;
}

void Flow::buffering_callback(const event_callback& callback) {
    on_buffering_callback_= callback;
}

void Flow::process_packet(PDU& pdu) {
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

void Flow::store_payload(uint32_t seq, const payload_type& payload) {
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

Flow::buffered_payload_type::iterator Flow::erase_iterator(buffered_payload_type::iterator iter) {
    buffered_payload_type::iterator output = iter;
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
        state_ = ESTABLISHED;
        seq_number_++;
    }
    else if (state_ == UNKNOWN && (tcp.flags() & TCP::SYN) != 0) {
        state_ = SYN_SENT;
        seq_number_ = tcp.seq();
    }
}

bool Flow::is_v6() const {
    return is_v6_;
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

Flow::payload_type& Flow::payload() {
    return payload_;
}

void Flow::state(State new_state) {
    state_ = new_state;
}

// Stream

Stream::Stream(const PDU& packet) 
: client_flow_(extract_client_flow(packet)),
  server_flow_(extract_server_flow(packet)), auto_cleanup_(true) {
    const TCP& tcp = packet.rfind_pdu<TCP>();
    // If it's a SYN, set the proper state
    if (tcp.flags() == TCP::SYN) {
        client_flow().state(Flow::SYN_SENT);
    }
}

void Stream::process_packet(PDU& packet) {
    if (client_flow_.packet_belongs(packet)) {
        client_flow_.process_packet(packet);
    }
    else if (server_flow_.packet_belongs(packet)) {
        server_flow_.process_packet(packet);
    }
    if (is_finished() && on_stream_closed_) {
        on_stream_closed_(*this);
    }
}

Flow& Stream::client_flow() {
    return client_flow_;
}

const Flow& Stream::client_flow() const {
    return client_flow_;
}

Flow& Stream::server_flow() {
    return server_flow_;
}

const Flow& Stream::server_flow() const {
    return server_flow_;
}

void Stream::stream_closed_callback(const stream_callback& callback) {
    on_stream_closed_ = callback;
}

void Stream::client_data_callback(const stream_callback& callback) {
    on_client_data_callback_ = callback;
}

void Stream::server_data_callback(const stream_callback& callback) {
    on_server_data_callback_ = callback;
}

void Stream::client_buffering_callback(const stream_callback& callback) {
    on_client_buffering_callback_ = callback;
}

void Stream::server_buffering_callback(const stream_callback& callback) {
    on_server_buffering_callback_ = callback;
}

bool Stream::is_finished() const {
    const Flow::State client_state = client_flow_.state();
    const Flow::State server_state = server_flow_.state();
    // If either peer sent a RST then the stream is done
    if (client_state == Flow::RST_SENT || server_state == Flow::RST_SENT) {
        return true;
    }
    else {
        // Otherwise, only finish if both sent a FIN
        return client_state == Flow::FIN_SENT && server_state == Flow::FIN_SENT;
    }
}

bool Stream::is_v6() const {
    return server_flow().is_v6();
}

IPv4Address Stream::client_addr_v4() const {
    return server_flow().dst_addr_v4();
}

IPv6Address Stream::client_addr_v6() const {
    return server_flow().dst_addr_v6();
}

IPv4Address Stream::server_addr_v4() const {
    return client_flow().dst_addr_v4();
}

IPv6Address Stream::server_addr_v6() const {
    return client_flow().dst_addr_v6();
}

uint16_t Stream::client_port() const {
    return server_flow().dport();
}

uint16_t Stream::server_port() const {
    return client_flow().dport();
}

const Stream::payload_type& Stream::client_payload() const {
    return client_flow().payload();
}

Stream::payload_type& Stream::client_payload() {
    return client_flow().payload();
}

const Stream::payload_type& Stream::server_payload() const {
    return server_flow().payload();
}

Stream::payload_type& Stream::server_payload() {
    return server_flow().payload();
}

Flow Stream::extract_client_flow(const PDU& packet) {
    const TCP* tcp = packet.find_pdu<TCP>();
    if (!tcp) {
        // TODO: define proper exception
        throw runtime_error("No TCP");
    }
    if (const IP* ip = packet.find_pdu<IP>()) {
        return Flow(ip->dst_addr(), tcp->dport(), tcp->seq());
    }
    else if (const IPv6* ip = packet.find_pdu<IPv6>()) {
        return Flow(ip->dst_addr(), tcp->dport(), tcp->seq());
    }
    else {
        // TODO: define proper exception
        throw runtime_error("No valid layer 3");
    }
}

Flow Stream::extract_server_flow(const PDU& packet) {
    const TCP* tcp = packet.find_pdu<TCP>();
    if (!tcp) {
        // TODO: define proper exception
        throw runtime_error("No TCP");
    }
    if (const IP* ip = packet.find_pdu<IP>()) {
        return Flow(ip->src_addr(), tcp->sport(), tcp->ack_seq());
    }
    else if (const IPv6* ip = packet.find_pdu<IPv6>()) {
        return Flow(ip->src_addr(), tcp->sport(), tcp->ack_seq());
    }
    else {
        // TODO: define proper exception
        throw runtime_error("No valid layer 3");
    }
}

void Stream::setup_flows_callbacks() {
    using std::placeholders::_1;
    client_flow_.data_callback(bind(&Stream::on_client_flow_data, this, _1));
    server_flow_.data_callback(bind(&Stream::on_server_flow_data, this, _1));
    client_flow_.buffering_callback(bind(&Stream::on_client_buffering, this, _1));
    server_flow_.buffering_callback(bind(&Stream::on_server_buffering, this, _1));
}

void Stream::auto_cleanup_payloads(bool value) {
    auto_cleanup_ = value;
}

void Stream::on_client_flow_data(const Flow& /*flow*/) {
    if (on_client_data_callback_) {
        on_client_data_callback_(*this);
    }
    if (auto_cleanup_) {
        client_payload().clear();
    }
}

void Stream::on_server_flow_data(const Flow& /*flow*/) {
    if (on_server_data_callback_) {
        on_server_data_callback_(*this);
    }
    if (auto_cleanup_) {
        server_payload().clear();
    }
}

void Stream::on_client_buffering(const Flow& flow) {
    if (on_client_buffering_callback_) {
        on_client_buffering_callback_(*this);
    }
}

void Stream::on_server_buffering(const Flow& flow) {
    if (on_server_buffering_callback_) {
        on_server_buffering_callback_(*this);
    }
}

// StreamFollower

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

void StreamFollower::new_stream_callback(const stream_callback& callback) {
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
}

bool StreamFollower::stream_id::operator<(const stream_id& rhs) const {
    return tie(min_address, min_address_port, max_address, max_address_port) <
        tie(rhs.min_address, rhs.min_address_port, rhs.max_address, rhs.max_address_port);
}

} // TCPIP
} // Tins

#endif // TINS_IS_CXX11