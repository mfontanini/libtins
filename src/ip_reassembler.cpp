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

#include "ip.h"
#include "rawpdu.h"
#include "constants.h"
#include "internals.h"
#include "ip_reassembler.h"

using std::make_pair;

namespace Tins {
namespace Internals {

IPv4Stream::IPv4Stream() 
: received_end_(false), transport_proto_(0xff), received_size_(), total_size_() { 

}

void IPv4Stream::add_fragment(IP* ip) {
    fragments_type::iterator it = fragments_.begin();
    uint16_t offset = extract_offset(ip);
    while (it != fragments_.end() && offset > it->offset()) {
        ++it;
    }
    // No duplicates plx
    if (it != fragments_.end() && it->offset() == offset) {
        return;
    }
    fragments_.insert(it, IPv4Fragment(ip->inner_pdu(), offset));
    received_size_ += ip->inner_pdu()->size();
    // If the MF flag is off
    if ((ip->flags() & IP::MORE_FRAGMENTS) == 0) {
        total_size_ = offset + ip->inner_pdu()->size();
        received_end_ = true;
    }
    if (offset == 0) {
        transport_proto_ = ip->protocol();
    }
}

bool IPv4Stream::is_complete() const {
    return received_end_ && received_size_ == total_size_;
}

PDU* IPv4Stream::allocate_pdu() const {
    PDU::serialization_type buffer;
    buffer.reserve(total_size_);
    // Check if we actually have all the data we need. Otherwise return nullptr;
    uint16_t expected = 0;
    for (fragments_type::const_iterator it = fragments_.begin(); it != fragments_.end(); ++it) {
        if (expected != it->offset()) {
            return 0;
        }
        expected = static_cast<uint16_t>(it->offset() + it->payload().size());
        buffer.insert(buffer.end(), it->payload().begin(), it->payload().end());
    }
    return Internals::pdu_from_flag(
        static_cast<Constants::IP::e>(transport_proto_),
        buffer.empty() ? 0 :& buffer[0],
        static_cast<uint32_t>(buffer.size())
    );
}

uint16_t IPv4Stream::extract_offset(const IP* ip) {
    return ip->fragment_offset() * 8;
}

} // Internals

IPv4Reassembler::IPv4Reassembler()
: technique_(NONE) {

}

IPv4Reassembler::IPv4Reassembler(OverlappingTechnique technique)
: technique_(technique) {

}

IPv4Reassembler::PacketStatus IPv4Reassembler::process(PDU& pdu) {
    IP* ip = pdu.find_pdu<IP>();
    if (ip && ip->inner_pdu()) {
        // There's fragmentation
        if (ip->is_fragmented()) {
            key_type key = make_key(ip);
            // Create it or look it up, it's the same
            Internals::IPv4Stream& stream = streams_[key];
            stream.add_fragment(ip);
            if (stream.is_complete()) {
                PDU* pdu = stream.allocate_pdu();
                // Erase this stream, since it's already assembled
                streams_.erase(key);
                // The packet is corrupt
                if (!pdu) {
                    return FRAGMENTED;
                }
                ip->inner_pdu(pdu);
                ip->fragment_offset(0);
                ip->flags(static_cast<IP::Flags>(0));
                return REASSEMBLED;
            }
            else {
                return FRAGMENTED;
            }
        }
    }
    return NOT_FRAGMENTED;
}

IPv4Reassembler::key_type IPv4Reassembler::make_key(const IP* ip) const {
    return make_pair(
        ip->id(),
        make_address_pair(ip->src_addr(), ip->dst_addr())
    );
}

IPv4Reassembler::address_pair IPv4Reassembler::make_address_pair(IPv4Address addr1, IPv4Address addr2) const {
    if (addr1 < addr2) {
        return make_pair(addr1, addr2);
    }
    else {
        return make_pair(addr2, addr1);
    }
}

void IPv4Reassembler::clear_streams() {
    streams_.clear();
}

void IPv4Reassembler::remove_stream(uint16_t id, IPv4Address addr1, IPv4Address addr2) {
    streams_.erase(
        make_pair(
            id, 
            make_address_pair(addr1, addr2)
        )
    );
}

} // Tins
