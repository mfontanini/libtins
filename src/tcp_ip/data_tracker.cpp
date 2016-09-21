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

#include "tcp_ip/data_tracker.h"

#ifdef TINS_HAVE_TCPIP

#include "internals.h"

using std::move;

using Tins::Internals::seq_compare;

namespace Tins {
namespace TCPIP {

DataTracker::DataTracker() 
: seq_number_(0), total_buffered_bytes_(0) {

}

DataTracker::DataTracker(uint32_t seq_number)
: seq_number_(seq_number), total_buffered_bytes_(0) {

}

bool DataTracker::process_payload(uint32_t seq, payload_type payload) {
    const uint32_t chunk_end = seq + payload.size();
    // If the end of the chunk ends before current sequence number, ignore it.
    if (seq_compare(chunk_end, seq_number_) < 0) {
        return false;
    }
    // If it starts before our sequence number, slice it
    if (seq_compare(seq, seq_number_) < 0) {
        const uint32_t diff = seq_number_ - seq;
        payload.erase(
            payload.begin(),
            payload.begin() + diff
        );
        seq = seq_number_;
    }
    bool added_some = false;
    // Store this payload
    store_payload(seq, move(payload));
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
    return added_some;
}

void DataTracker::advance_sequence(uint32_t seq) {
    if (seq_compare(seq, seq_number_) <= 0) {
        return;
    }

    for (auto it = buffered_payload_.begin(); it != buffered_payload_.end();) {
        if (seq_compare(it->first, seq) <= 0) {
            total_buffered_bytes_ -= it->second.size();
            it = buffered_payload_.erase(it);
        } else {
            it++;
        }
    }

    seq_number_ = seq;
}

uint32_t DataTracker::sequence_number() const {
    return seq_number_;
}

void DataTracker::sequence_number(uint32_t seq) {
    seq_number_ = seq;
}

const DataTracker::payload_type& DataTracker::payload() const {
    return payload_;
}

DataTracker::payload_type& DataTracker::payload() {
    return payload_;
}

const DataTracker::buffered_payload_type& DataTracker::buffered_payload() const {
    return buffered_payload_;
}

DataTracker::buffered_payload_type& DataTracker::buffered_payload() {
    return buffered_payload_;
}

uint32_t DataTracker::total_buffered_bytes() const {
    return total_buffered_bytes_;
}

void DataTracker::store_payload(uint32_t seq, payload_type payload) {
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

DataTracker::buffered_payload_type::iterator
DataTracker::erase_iterator(buffered_payload_type::iterator iter) {
    buffered_payload_type::iterator output = iter;
    total_buffered_bytes_ -= iter->second.size();
    ++output;
    buffered_payload_.erase(iter);
    if (output == buffered_payload_.end()) {
        output = buffered_payload_.begin();
    }
    return output;
}

} // TCPIP
} // Tins

#endif // TINS_HAVE_TCPIP
