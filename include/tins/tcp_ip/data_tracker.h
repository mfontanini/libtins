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

#ifndef TINS_TCP_IP_DATA_TRACKER_H
#define TINS_TCP_IP_DATA_TRACKER_H

#include <vector>
#include <map>
#include <stdint.h>
#include "../config.h"
#include "../macros.h"

#ifdef TINS_HAVE_TCPIP

namespace Tins {
namespace TCPIP {

/**
 * \class DataTracker
 *
 * Stores and tracks data in a TCP stream, reassembling segments, handling 
 * out of order packets, etc.
 */
class TINS_API DataTracker {
public:
    /** 
     * The type used to store the payload
     */
    typedef std::vector<uint8_t> payload_type;

    /**
     * The type used to store the buffered payload
     */
    typedef std::map<uint32_t, payload_type> buffered_payload_type;

    /**
     * Default constructs an instance
     */
    DataTracker();

    /**
     * \brief Constructs an instance using the given sequence number as the initial one
     *
     * \param seq_number The sequence number to use
     */
    DataTracker(uint32_t seq_number);

    /**
     * \brief Processes the given payload
     *
     * This will buffer the given data on the payload buffer or store it on the
     * buffered payload map, depending the sequence number given. 
     *
     * This method returns true iff any data was added to the payload buffer. That is
     * if this method returns true, then the size of the payload will be greater than
     * what it was before calling the function.
     *
     * \brief seq The payload's sequence number
     * \brief payload The payload to process
     * \return true iff any data was added to the payload buffer
     */
    bool process_payload(uint32_t seq, payload_type payload);

    /**
     * \brief Skip forward to a sequence number
     *
     * This allows to recover from packetloss, if we just do not see all packets of
     * an original stream. This recovery can only sensibly triggered from the application
     * layer.
     *
     * The method does nothing, if the sequence number is smaller or equal to the
     * current number.
     *
     * This method is particularly useful to call from an out of order callback, if
     * the application wants to skip forward to this out of order block. The application
     * will then get the normal data callback!
     *
     * The method cleans the buffer from all no longer needed fragments.
     *
     * IMPORTANT: If you call this method with a sequence number that is not exactly a
     * TCP fragment boundary, the flow will never recover from this.
     *
     * \param seq The seqeunce number to skip to.
     */
    void advance_sequence(uint32_t seq);

    /**
     * Retrieves the current sequence number
     */
    uint32_t sequence_number() const;

    /**
     * Sets the current sequence number
     */
    void sequence_number(uint32_t seq);

    /** 
     * Retrieves the available payload (const)
     */
    const payload_type& payload() const;

    /** 
     * Retrieves the available payload
     */
    payload_type& payload();

    /** 
     * Retrieves the buffered payload (const)
     */
    const buffered_payload_type& buffered_payload() const;

    /** 
     * Retrieves the buffered payload
     */
    buffered_payload_type& buffered_payload();

    /**
     * Retrieves the total amount of buffered bytes
     */
    uint32_t total_buffered_bytes() const;
private:
    void store_payload(uint32_t seq, payload_type payload);
    buffered_payload_type::iterator erase_iterator(buffered_payload_type::iterator iter);

    payload_type payload_;
    buffered_payload_type buffered_payload_;
    uint32_t seq_number_;
    uint32_t total_buffered_bytes_;
};

} // TCPIP
} // Tins

#endif // TINS_HAVE_TCPIP

#endif // TINS_TCP_IP_DATA_TRACKER_H
