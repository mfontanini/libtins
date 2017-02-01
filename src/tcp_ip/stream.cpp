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

#include "tcp_ip/stream.h"

#ifdef TINS_HAVE_TCPIP

#include <limits>
#include <algorithm>
#include "memory.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "tcp.h"
#include "ip.h"
#include "ipv6.h"
#include "ethernetII.h"
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

Stream::Stream(PDU& packet, const timestamp_type& ts) 
: client_flow_(extract_client_flow(packet)),
  server_flow_(extract_server_flow(packet)), create_time_(ts), 
  last_seen_(ts), auto_cleanup_client_(true), auto_cleanup_server_(true),
  is_partial_stream_(false), directions_recovery_mode_enabled_(0) {
    const EthernetII* eth = packet.find_pdu<EthernetII>();
    if (eth) {
        client_hw_addr_ = eth->src_addr();
        server_hw_addr_ = eth->dst_addr();
    }
    const TCP& tcp = packet.rfind_pdu<TCP>();
    // If this is not the first packet of a stream (SYN), then it's a partial stream
    is_partial_stream_ = tcp.flags() != TCP::SYN;
}

void Stream::process_packet(PDU& packet, const timestamp_type& ts) {
    last_seen_ = ts;
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

void Stream::process_packet(PDU& packet) {
    return process_packet(packet, timestamp_type(0));
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

void Stream::stream_closed_callback(const stream_callback_type& callback) {
    on_stream_closed_ = callback;
}

void Stream::client_data_callback(const stream_callback_type& callback) {
    on_client_data_callback_ = callback;
}

void Stream::server_data_callback(const stream_callback_type& callback) {
    on_server_data_callback_ = callback;
}

void Stream::client_out_of_order_callback(const stream_packet_callback_type& callback) {
    on_client_out_of_order_callback_ = callback;
}

void Stream::server_out_of_order_callback(const stream_packet_callback_type& callback) {
    on_server_out_of_order_callback_ = callback;
}

void Stream::ignore_client_data() {
    client_flow().ignore_data_packets();
}

void Stream::ignore_server_data() {
    server_flow().ignore_data_packets();
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

const Stream::hwaddress_type& Stream::client_hw_addr() const {
    return client_hw_addr_;
}

const Stream::hwaddress_type& Stream::server_hw_addr() const {
    return server_hw_addr_;
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

const Stream::timestamp_type& Stream::create_time() const {
    return create_time_;
}

const Stream::timestamp_type& Stream::last_seen() const {
    return last_seen_;
}

Flow Stream::extract_client_flow(const PDU& packet) {
    const TCP* tcp = packet.find_pdu<TCP>();
    if (!tcp) {
        throw invalid_packet();
    }
    if (const IP* ip = packet.find_pdu<IP>()) {
        return Flow(ip->dst_addr(), tcp->dport(), tcp->seq());
    }
    else if (const IPv6* ip = packet.find_pdu<IPv6>()) {
        return Flow(ip->dst_addr(), tcp->dport(), tcp->seq());
    }
    else {
        throw invalid_packet();
    }
}

Flow Stream::extract_server_flow(const PDU& packet) {
    const TCP* tcp = packet.find_pdu<TCP>();
    if (!tcp) {
        throw invalid_packet();
    }
    if (const IP* ip = packet.find_pdu<IP>()) {
        return Flow(ip->src_addr(), tcp->sport(), tcp->ack_seq());
    }
    else if (const IPv6* ip = packet.find_pdu<IPv6>()) {
        return Flow(ip->src_addr(), tcp->sport(), tcp->ack_seq());
    }
    else {
        throw invalid_packet();
    }
}

void Stream::setup_flows_callbacks() {
    using namespace std::placeholders;

    client_flow_.data_callback(bind(&Stream::on_client_flow_data, this, _1));
    server_flow_.data_callback(bind(&Stream::on_server_flow_data, this, _1));
    client_flow_.out_of_order_callback(bind(&Stream::on_client_out_of_order,
                                            this, _1, _2, _3));
    server_flow_.out_of_order_callback(bind(&Stream::on_server_out_of_order,
                                            this, _1, _2, _3));
}

void Stream::auto_cleanup_payloads(bool value) {
    auto_cleanup_client_data(value);
    auto_cleanup_server_data(value);
}

void Stream::auto_cleanup_client_data(bool value) {
    auto_cleanup_client_ = value;
}

void Stream::auto_cleanup_server_data(bool value) {
    auto_cleanup_server_ = value;
}

void Stream::enable_ack_tracking() {
    client_flow().enable_ack_tracking();
    server_flow().enable_ack_tracking();
}

bool Stream::ack_tracking_enabled() const {
    return client_flow().ack_tracking_enabled() && server_flow().ack_tracking_enabled();
}

bool Stream::is_partial_stream() const {
    return is_partial_stream_;
}

void Stream::enable_recovery_mode(uint32_t recovery_window) {
    using namespace std::placeholders;
    client_out_of_order_callback(bind(&Stream::client_recovery_mode_handler, _1, _2, _3,
                                 client_flow_.sequence_number() + recovery_window,
                                 on_client_out_of_order_callback_));
    server_out_of_order_callback(bind(&Stream::server_recovery_mode_handler, _1, _2, _3,
                                 server_flow_.sequence_number() + recovery_window,
                                 on_server_out_of_order_callback_));
    directions_recovery_mode_enabled_ = 2;
}

bool Stream::is_recovery_mode_enabled() const {
    return directions_recovery_mode_enabled_ > 0;
}

void Stream::on_client_flow_data(const Flow& /*flow*/) {
    if (on_client_data_callback_) {
        on_client_data_callback_(*this);
    }
    if (auto_cleanup_client_) {
        client_payload().clear();
    }
}

void Stream::on_server_flow_data(const Flow& /*flow*/) {
    if (on_server_data_callback_) {
        on_server_data_callback_(*this);
    }
    if (auto_cleanup_server_) {
        server_payload().clear();
    }
}

void Stream::on_client_out_of_order(const Flow& /*flow*/, uint32_t seq, const payload_type& payload) {
    if (on_client_out_of_order_callback_) {
        on_client_out_of_order_callback_(*this, seq, payload);
    }
}

void Stream::on_server_out_of_order(const Flow& /*flow*/, uint32_t seq, const payload_type& payload) {
    if (on_server_out_of_order_callback_) {
        on_server_out_of_order_callback_(*this, seq, payload);
    }
}

void Stream::client_recovery_mode_handler(Stream& stream, uint32_t sequence_number,
                                          const payload_type& payload,
                                          uint32_t recovery_sequence_number_end,
                                          const stream_packet_callback_type& original_callback) {
    if (original_callback) {
        original_callback(stream, sequence_number, payload);
    }
    if (!recovery_mode_handler(stream.client_flow(), sequence_number,
                               recovery_sequence_number_end)) {
        stream.directions_recovery_mode_enabled_--;
        stream.client_out_of_order_callback(original_callback);
    }
}

void Stream::server_recovery_mode_handler(Stream& stream, uint32_t sequence_number,
                                          const payload_type& payload,
                                          uint32_t recovery_sequence_number_end,
                                          const stream_packet_callback_type& original_callback) {
    if (original_callback) {
        original_callback(stream, sequence_number, payload);
    }
    if (!recovery_mode_handler(stream.server_flow(), sequence_number,
                               recovery_sequence_number_end)) {
        stream.directions_recovery_mode_enabled_--;
        stream.server_out_of_order_callback(original_callback);
    }
}

bool Stream::recovery_mode_handler(Flow& flow, uint32_t sequence_number,
                                   uint32_t recovery_sequence_number_end) {
    // If this packet comes after our sequence number (would create a hole), skip it
    if (sequence_number > flow.sequence_number() &&
        sequence_number <= recovery_sequence_number_end) {
        flow.advance_sequence(sequence_number);
    }
    // Return true iff we need to keep being in recovery mode
    return recovery_sequence_number_end > sequence_number;
}

} // TCPIP
} // Tins

#endif // TINS_HAVE_TCPIP
