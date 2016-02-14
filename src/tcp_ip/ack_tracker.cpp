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

#include "tcp_ip/ack_tracker.h"

#ifdef HAVE_ACK_TRACKER

#include <limits>
#include "tcp.h"
#include "internals.h"

using std::vector;
using std::numeric_limits;

using Tins::Internals::seq_compare;

namespace Tins {
namespace TCPIP {

// AckedRange

AckedRange::AckedRange(uint32_t first, uint32_t last) 
: first_(first), last_(last) {

}

AckedRange::interval_type AckedRange::next() {
    uint32_t interval_first = first_;
    // Regular case
    if (first_ <= last_) {
        first_ = last_ + 1;
        return interval_type::closed(interval_first, last_);
    }
    else {
        // Range wraps around 
        first_ = 0;
        return interval_type::closed(interval_first, numeric_limits<uint32_t>::max());
    }
}

bool AckedRange::has_next() const {
    return seq_compare(first_, last_) <= 0;
}

uint32_t AckedRange::first() const {
    return first_;
}

uint32_t AckedRange::last() const {
    return last_;
}

// AckTracker

AckTracker::AckTracker()
: ack_number_(0), use_sack_(false) {
    
}

AckTracker::AckTracker(uint32_t initial_ack, bool use_sack)
: ack_number_(initial_ack), use_sack_(use_sack) {

}

void AckTracker::process_packet(const PDU& packet) {
    const TCP* tcp = packet.find_pdu<TCP>();
    if (!tcp) {
        return;
    }
    if (seq_compare(tcp->ack_seq(), ack_number_) > 0) {
        cleanup_sacked_intervals(ack_number_, tcp->ack_seq());
        ack_number_ = tcp->ack_seq();
    }
    if (use_sack_) {
        const TCP::option* sack_option = tcp->search_option(TCP::SACK);
        if (sack_option) {
            TCP::sack_type sack = sack_option->to<TCP::sack_type>();
            process_sack(sack);
        }
    }
}

void AckTracker::process_sack(const vector<uint32_t>& sack) {
    for (size_t i = 1; i < sack.size(); i += 2) {
        // Left edge must be lower than right edge
        if (seq_compare(sack[i - 1], sack[i]) < 0) {
            AckedRange range(sack[i - 1], sack[i] - 1);
            // If this range starts after our current ack number
            if (seq_compare(range.first(), ack_number_) > 0) {
                while (range.has_next()) {
                    acked_intervals_.insert(range.next());
                }
            }
        }
    }
}

void AckTracker::cleanup_sacked_intervals(uint32_t old_ack, uint32_t new_ack) {
    AckedRange range(old_ack, new_ack);
    while (range.has_next()) {
        acked_intervals_.erase(range.next());
    }
}

void AckTracker::use_sack() {
    use_sack_ = true;
}

uint32_t AckTracker::ack_number() const {
    return ack_number_;
}

const AckTracker::interval_set_type& AckTracker::acked_intervals() const {
    return acked_intervals_;
}

} // TCPIP
} // Tins

#endif // HAVE_ACK_TRACKER
