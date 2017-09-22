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

#ifndef TINS_TCP_IP_ACK_TRACKER_H
#define TINS_TCP_IP_ACK_TRACKER_H

#include <tins/config.h>

#ifdef TINS_HAVE_ACK_TRACKER

#include <vector>
#include <boost/icl/interval_set.hpp>
#include <tins/macros.h>

namespace Tins {

class PDU;

namespace TCPIP {

/**
 * \brief Represents an acknowledged segment range
 *
 * The interval represented by this range is a closed interval [first, last].
 */
class TINS_API AckedRange {
public:
    typedef boost::icl::discrete_interval<uint32_t> interval_type;

    /**
     * \brief Constructs an acked range
     *
     * \param first The first acked byte
     * \param last The last acked byte (inclusive)
     */
    AckedRange(uint32_t first, uint32_t last);

    /**
     * \brief Gets the next acked interval in this range
     *
     * If has_next() == false, then this returns an empty interval
     */
    interval_type next();

    /**
     * Indicates whether there is still some non-consumed acked-interval in this
     * range
     */
    bool has_next() const;

    /**
     * Gets the first index acked by this range
     */
    uint32_t first() const;

    /**
     * Gets the last index acked by this range
     */
    uint32_t last() const;
private:
    uint32_t first_;
    uint32_t last_;
};

/**
 * \brief Allows tracking acknowledged intervals in a TCP stream
 */
class TINS_API AckTracker {
public:
    /**
     * The type used to store ACKed intervals
     */
    typedef boost::icl::interval_set<uint32_t> interval_set_type;

    /**
     * Default constructor
     */
    AckTracker();

    /**
     * \brief Construct an instance using some attributes
     *
     * \param intial_ack The initial ACK number to use
     * \param use_sack Indicate whether to use Selective ACKs to track ACK numbers
     */
    AckTracker(uint32_t initial_ack, bool use_sack = true);

    /**
     * \brief Process a packet
     */
    void process_packet(const PDU& packet);

    /**
     * \brief Indicates whether Selective ACKs should be processed
     */
    void use_sack();

    /**
     * Retrieves the current ACK number in this tracker
     */
    uint32_t ack_number() const;

    /**
     * \brief Retrieves all acked intervals by Selective ACKs
     */
    const interval_set_type& acked_intervals() const; 

    /**
     * \brief Indicates whether the given segment has been already ACKed
     *
     * \param sequence_number The segment's sequence number
     * \param length The segment's length
     */
    bool is_segment_acked(uint32_t sequence_number, uint32_t length) const;
private:
    void process_sack(const std::vector<uint32_t>& sack);
    void cleanup_sacked_intervals(uint32_t old_ack, uint32_t new_ack);

    interval_set_type acked_intervals_;
    uint32_t ack_number_;
    bool use_sack_;
};

} // TCPIP
} // Tins

#endif // TINS_HAVE_ACK_TRACKER

#endif // TINS_TCP_IP_ACK_TRACKER_H

