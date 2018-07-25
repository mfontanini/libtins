/*
 * Copyright (c) 2017, Matias Fontanini
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

#include <algorithm>
#include <tins/ip.h>
#include <tins/rawpdu.h>
#include <tins/constants.h>
#include <tins/ip_reassembler.h>
#include <tins/detail/pdu_helpers.h>

using std::make_pair;
using std::out_of_range;

namespace Tins {
namespace Internals {

uint16_t IPv4Fragment::trim(uint16_t amount) {
    if (amount > payload_.size()) {
        amount = payload_.size();
    }
    offset_ += amount;
    payload_.erase(
        payload_.begin(),
        payload_.begin() + amount);
    return amount; // report deleted bytes
}

IPv4Stream::IPv4Stream() 
: received_size_(), total_size_(), received_end_(false) {

}

size_t IPv4Stream::add_fragment(IP* ip) {
    const size_t before_size = received_size_;
    const uint16_t offset = extract_offset(ip);
    uint16_t expected_offset = 0;
    fragments_type::iterator it = fragments_.begin();
    while (it != fragments_.end() && offset > it->offset()) {
        expected_offset = static_cast<uint16_t>(it->offset() + it->size());
        ++it;
    }

    // No duplicates plx
    /*if (it != fragments_.end() && it->offset() == offset) {
        return;
    }*/

    // overlap handling
    /*fragments_.insert(it, IPv4Fragment(ip->inner_pdu(), offset));*/
    IPv4Fragment frag(ip->inner_pdu(), offset);
    if (expected_offset > offset) {
        frag.trim(expected_offset - offset);
    }
    size_t frag_size = frag.size();
    if(frag_size == 0) {
        return 0;
    }
    if(static_cast<size_t>(frag.offset()) + frag_size > 65535) {
        return 0;
    }
    expected_offset = static_cast<uint16_t>(frag.offset() + frag_size);
    while (it != fragments_.end() && it->offset() < expected_offset) {
        received_size_ -= it->trim(expected_offset - it->offset());
        if (it->size() == 0) {
            it = fragments_.erase(it);
        }
        else {
            break;
        }
    }

    // I wonder whether the copying of the payload is/can be optimized away
    fragments_.insert(it, frag);
    received_size_ += frag_size;
    // If the MF flag is off
    if ((ip->flags() & IP::MORE_FRAGMENTS) == 0) {
        total_size_ = expected_offset;
        received_end_ = true;
    }
    if (frag.offset() == 0) {
        // Release the inner PDU, store this first fragment and restore the inner PDU
        PDU* inner_pdu = ip->release_inner_pdu();
        first_fragment_ = *ip;
        ip->inner_pdu(inner_pdu);
    }
    return received_size_ - before_size;
}

bool IPv4Stream::is_complete() const {
    // If we haven't received the last chunk of we haven't received all the data,
    // then we're not complete
    if (!received_end_ || received_size_ != total_size_) {
        return false;
    }
    // Make sure the first fragment has offset 0
    return fragments_.begin()->offset() == 0;
}

PDU* IPv4Stream::allocate_pdu() const {
    PDU::serialization_type buffer;
    buffer.reserve(total_size_);
    // Check if we actually have all the data we need. Otherwise return nullptr;
    size_t expected = 0;
    for (fragments_type::const_iterator it = fragments_.begin(); it != fragments_.end(); ++it) {
        if (expected != it->offset()) {
            return 0;
        }
        expected = it->offset() + it->payload().size();
        buffer.insert(buffer.end(), it->payload().begin(), it->payload().end());
    }
    return Internals::pdu_from_flag(
        static_cast<Constants::IP::e>(first_fragment_.protocol()),
        buffer.empty() ? 0 :& buffer[0],
        static_cast<uint32_t>(buffer.size())
    );
}

const IP& IPv4Stream::first_fragment() const {
    return first_fragment_;
}

uint16_t IPv4Stream::extract_offset(const IP* ip) {
    return ip->fragment_offset() * 8;
}

} // Internals

const size_t IPv4Reassembler::MAX_BUFFERED_BYTES = 256*1024;
const size_t IPv4Reassembler::BUFFERED_BYTES_LOW_THRESHOLD = 192*1024;

IPv4Reassembler::IPv4Reassembler()
: technique_(BSD), buffered_bytes_() {

}

IPv4Reassembler::IPv4Reassembler(OverlappingTechnique technique)
: technique_(technique), buffered_bytes_()  {

}

IPv4Reassembler::PacketStatus IPv4Reassembler::process(PDU& pdu) {
    IP* ip = pdu.find_pdu<IP>();
    if (ip && ip->inner_pdu()) {
        // There's fragmentation
        if (ip->is_fragmented()) {
            key_type key = make_key(ip);
            // Create it or look it up, it's the same
            Internals::IPv4Stream& stream = get_stream(key);
            buffered_bytes_ += stream.add_fragment(ip);
            if (stream.is_complete()) {
                PDU* pdu = stream.allocate_pdu();
                // Use all field values from the first fragment
                *ip = stream.first_fragment();

                // Erase this stream, since it's already assembled
                remove_stream(key);
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
                if (buffered_bytes_ > MAX_BUFFERED_BYTES) {
                    prune_streams();
                }
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

Internals::IPv4Stream& IPv4Reassembler::get_stream(key_type key) {
    Internals::IPv4Stream *stream_ptr;
    try {
        ordered_streams_type::iterator& it = streams_.at(key); // may throw out_of_range
        stream_ptr = it->second;
        ordered_streams_.erase(it);
    }
    catch (out_of_range&) {
        stream_ptr = new Internals::IPv4Stream();
    }
    ordered_streams_type::iterator it2 = ordered_streams_.insert(ordered_streams_.end(), make_pair(key,stream_ptr));
    streams_[key] = it2;
    return *stream_ptr;
}

void IPv4Reassembler::prune_streams() {
    while (buffered_bytes_ > BUFFERED_BYTES_LOW_THRESHOLD) {
        remove_stream(ordered_streams_.begin()->first);
    }
}

void IPv4Reassembler::clear_streams() {
    streams_.clear();
    ordered_streams_.clear();
    buffered_bytes_ = 0;
}

void IPv4Reassembler::remove_stream(key_type key) {
    try {
        ordered_streams_type::iterator& it = streams_.at(key); // may throw out_of_range
        Internals::IPv4Stream *stream_ptr = it->second;
        buffered_bytes_ -= stream_ptr->size();
        ordered_streams_.erase(it);
        streams_.erase(key);
        delete stream_ptr;
    }
    catch (out_of_range&) { }
}

void IPv4Reassembler::remove_stream(uint16_t id, IPv4Address addr1, IPv4Address addr2) {
    key_type key = make_pair(
        id, 
        make_address_pair(addr1, addr2)
    );
    remove_stream(key);
}

} // Tins
