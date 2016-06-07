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

#include "tcp_ip/stream_identifier.h"

#ifdef TINS_HAVE_TCPIP

#include <algorithm>
#include <tuple>
#include "memory_helpers.h"
#include "tcp.h"
#include "udp.h"
#include "ip.h"
#include "ipv6.h"
#include "exceptions.h"
#include "tcp_ip/stream.h"

using std::swap;
using std::tie;

using Tins::Memory::OutputMemoryStream;

namespace Tins {
namespace TCPIP {

StreamIdentifier::StreamIdentifier() 
: min_address_port(0), max_address_port(0) {
    min_address.fill(0);
    max_address.fill(0);
}

StreamIdentifier::StreamIdentifier(const address_type& client_addr,
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

bool StreamIdentifier::operator<(const StreamIdentifier& rhs) const {
    return tie(min_address, max_address, min_address_port, max_address_port) <
           tie(rhs.min_address, rhs.max_address, rhs.min_address_port, rhs.max_address_port);
}

bool StreamIdentifier::operator==(const StreamIdentifier& rhs) const {
    return tie(min_address, min_address_port, max_address, max_address_port) ==
           tie(rhs.min_address, rhs.min_address_port, rhs.max_address, rhs.max_address_port);
}

StreamIdentifier StreamIdentifier::make_identifier(const PDU& packet) {
    uint16_t source_port;
    uint16_t dest_port;
    // Extract source and dest ports
    if (const TCP* tcp = packet.find_pdu<TCP>()) {
        source_port = tcp->sport();
        dest_port = tcp->dport();
    }
    else if (const UDP* udp = packet.find_pdu<UDP>()) {
        source_port = udp->sport();
        dest_port = udp->dport();
    }
    else {
        throw invalid_packet();
    }
    // Extract layer 3 and build the identifier
    if (const IP* ip = packet.find_pdu<IP>()) {
        return StreamIdentifier(serialize(ip->src_addr()), source_port,
                                serialize(ip->dst_addr()), dest_port);
    }
    else if (const IPv6* ip = packet.find_pdu<IPv6>()) {
        return StreamIdentifier(serialize(ip->src_addr()), source_port,
                                serialize(ip->dst_addr()), dest_port);
    }
    else {
        throw invalid_packet();
    }
}

StreamIdentifier StreamIdentifier::make_identifier(const Stream& stream) {
    if (stream.is_v6()) {
      return StreamIdentifier(serialize(stream.client_addr_v6()), stream.client_port(),
                              serialize(stream.server_addr_v6()), stream.server_port());
    } else {
      return StreamIdentifier(serialize(stream.client_addr_v4()), stream.client_port(),
                              serialize(stream.server_addr_v4()), stream.server_port());
    }
}

StreamIdentifier::address_type StreamIdentifier::serialize(IPv4Address address) {
    address_type addr;
    OutputMemoryStream output(addr.data(), addr.size());
    addr.fill(0);
    output.write(address);
    return addr; 
}

StreamIdentifier::address_type StreamIdentifier::serialize(const IPv6Address& address) {
    address_type addr;
    OutputMemoryStream output(addr.data(), addr.size());
    addr.fill(0);
    output.write(address);
    return addr;
}

} // TCPIP
} // Tins

#endif // TINS_HAVE_TCPIP
