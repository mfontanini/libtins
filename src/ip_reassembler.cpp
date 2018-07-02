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

#include <tins/ip.h>
#include <tins/constants.h>
#include <tins/ip_reassembler.h>
#include <tins/detail/pdu_helpers.h>

using std::make_pair;

namespace Tins {
namespace Internals {

IPv4Stream::IPv4Stream() 
: received_size_(), total_size_(), received_end_(false), 
    start_time_point_(std::chrono::system_clock::now()) {

}

void IPv4Stream::add_fragment(IP* ip) {
    const uint16_t offset = extract_offset(ip);
    fragments_type::iterator it = fragments_.begin();
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
        // Release the inner PDU, store this first fragment and restore the inner PDU
        PDU* inner_pdu = ip->release_inner_pdu();
        first_fragment_ = *ip;
        ip->inner_pdu(inner_pdu);
    }
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

size_t IPv4Stream::number_fragments() const {
    return fragments_.size();
}

IPv4Stream::time_point IPv4Stream::start_time_point() const {
    return start_time_point_;
}

uint16_t IPv4Stream::extract_offset(const IP* ip) {
    return ip->fragment_offset() * 8;
}

} // Internals

IPv4Reassembler::IPv4Reassembler()
: technique_(NONE), max_number_packets_to_stream_(0), 
    stream_timeout_ms_(0), origin_cycle_time_(std::chrono::system_clock::now()),
        stream_overflow_callback_(0), stream_timeout_callback_(0),
            total_number_complete_packages_(0), total_number_damaged_packages_(0) {

}

IPv4Reassembler::IPv4Reassembler(OverlappingTechnique technique)
: technique_(technique), max_number_packets_to_stream_(0), 
    stream_timeout_ms_(0), origin_cycle_time_(std::chrono::system_clock::now()),
        stream_overflow_callback_(0), stream_timeout_callback_(0),
            total_number_complete_packages_(0), total_number_damaged_packages_(0) {

}

IPv4Reassembler::PacketStatus IPv4Reassembler::process(PDU& pdu) {
    // Removal of expired streams
    removal_expired_streams();

    IP* ip = pdu.find_pdu<IP>();
    if (ip && ip->inner_pdu()) {
        // There's fragmentation
        if (ip->is_fragmented()) {
            key_type key = make_key(ip);
            // Create it or look it up, it's the same
            streams_type::iterator stream_it = streams_.find(key); 
            Internals::IPv4Stream& stream = (stream_it != streams_.end() ? stream_it->second : streams_[key]);

            stream.add_fragment(ip);
            if (stream.is_complete()) {
                ++total_number_complete_packages_;

                PDU* pdu = stream.allocate_pdu();
                // Use all field values from the first fragment
                *ip = stream.first_fragment();

                // Erase this stream, since it's already assembled
                streams_.erase(key);

                // The packet is corrupt
                if (!pdu) {
                    ++total_number_damaged_packages_;
                    return FRAGMENTED;
                }
                ip->inner_pdu(pdu);
                ip->fragment_offset(0);
                ip->flags(static_cast<IP::Flags>(0));

                return REASSEMBLED;
            }
            
            // Only non-complete packages fall into the list
            if (stream_timeout_ms_ && stream_it == streams_.end()) {
                streams_history_.emplace_back(key, stream.start_time_point());
            }

            // Tracking overflow stream
            if (max_number_packets_to_stream_
                && stream.number_fragments() >= max_number_packets_to_stream_)
            {
                if (stream_overflow_callback_)
                {
                    PDU* pdu = stream.allocate_pdu();

                    // The packet is not corrupt
                    if (pdu) {
                        stream_overflow_callback_(*pdu);
                        delete pdu;
                    } else {
                        ++total_number_damaged_packages_;
                    }
                }

                // Erase this stream
                streams_.erase(key);
            }

            return FRAGMENTED;
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

void IPv4Reassembler::removal_expired_streams()
{
    if (!stream_timeout_ms_ || streams_history_.empty()) return;

    Internals::IPv4Stream::time_point now = std::chrono::system_clock::now();
    auto step = std::chrono::duration_cast<std::chrono::seconds>(now - origin_cycle_time_);
    if (std::chrono::seconds(time_to_check_s_) < step) {
        return;
    }

    while (!streams_history_.empty()) {
        streams_history::value_type & history_front = streams_history_.front();
        streams_type::iterator stream_it = streams_.find(history_front.first);
        if (stream_it == streams_.end()) {
            streams_history_.pop_front();
            continue;
        } 
        Internals::IPv4Stream& stream_tmp = stream_it->second; 
        if (stream_tmp.start_time_point() != history_front.second) {
            streams_history_.pop_front();
            continue;
        }

        auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - history_front.second);
        if ((size_t)diff.count() > stream_timeout_ms_) {
            if (stream_timeout_callback_) {
                PDU* pdu = stream_tmp.allocate_pdu();

                // The packet is not corrupt
                if (pdu) {
                    stream_timeout_callback_(*pdu);
                    delete pdu;
                } else {
                    ++total_number_damaged_packages_;
                }
            }
            // Erase this stream
            streams_.erase(history_front.first);
            streams_history_.pop_front();
        } else break;
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

void IPv4Reassembler::set_max_number_packets_to_stream(size_t max_number, StreamCallback callback) {
    max_number_packets_to_stream_ = max_number;
    stream_overflow_callback_ = callback;
}

void IPv4Reassembler::set_timeout_to_stream(size_t stream_timeout_ms, size_t time_to_check_s, StreamCallback callback) {
    stream_timeout_ms_ = stream_timeout_ms;
    time_to_check_s_ = time_to_check_s;
    stream_timeout_callback_ = callback;
}

size_t IPv4Reassembler::total_number_complete_packages() const {
    return total_number_complete_packages_;
}

size_t IPv4Reassembler::total_number_damaged_packages() const {
    return total_number_damaged_packages_;
}

size_t IPv4Reassembler::current_number_incomplete_packages() const {
    return streams_.size();
}

} // Tins
