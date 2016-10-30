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

#ifndef TINS_TCP_IP_STREAM_FOLLOWER_H
#define TINS_TCP_IP_STREAM_FOLLOWER_H

#include "../config.h"

#ifdef TINS_HAVE_TCPIP

#include <map>
#include "stream.h"
#include "stream_identifier.h"

namespace Tins {

class PDU;
class TCP;
class IPv4Address;
class IPv6Address;
class Packet;

namespace TCPIP {

/**
 * \brief Represents a class that follows TCP and reassembles streams
 *
 * This class processes packets and whenever it detects a new connection
 * being open, it starts tracking it. This will follow all data sent by
 * each peer and make it available to the user in a simple way.
 *
 * In order to use this class, just create an instance and set the 
 * new stream callback to some function that you want:
 *
 * \code
 * void on_new_stream(TCPStream& stream) {
 *     // Do something with it.
 *     // This is the perfect time to set the stream's client/server 
 *     // write callbacks so you are notified whenever there's new
 *     // data on the stream
 * }
 *
 * // Create it 
 * StreamFollower follower;
 * // Set the callback
 * follower.new_stream_callback(&on_new_stream);
 * \endcode
 */
class TINS_API StreamFollower {
public:
    /**
     * The type used for callbacks
     */
    typedef Stream::stream_callback_type stream_callback_type;

    /**
     * The type used to identify streams 
     */
    typedef StreamIdentifier stream_id;

    /**
     * Enum to indicate the reason why a stream was terminated
     */
    enum TerminationReason {
        TIMEOUT, ///< The stream was terminated due to a timeout
        BUFFERED_DATA, ///< The stream was terminated because it had too much buffered data
        SACKED_SEGMENTS ///< The stream was terminated because it had too many SACKed segments
    };

    /**
     * \brief The type used for stream termination callbacks
     *
     * \sa StreamFollower::stream_termination_callback
     */
    typedef std::function<void(Stream&, TerminationReason)> stream_termination_callback_type;

    /** 
     * Default constructor
     */
    StreamFollower();

    /** 
     * \brief Processes a packet
     *
     * This will detect if this packet belongs to an existing stream 
     * and process it, or if it belongs to a new one, in which case it
     * starts tracking it.
     *
     * \param packet The packet to be processed
     */
    void process_packet(PDU& packet);

    /** 
     * \brief Processes a packet
     *
     * This will detect if this packet belongs to an existing stream 
     * and process it, or if it belongs to a new one, in which case it
     * starts tracking it.
     *
     * \param packet The packet to be processed
     */
    void process_packet(Packet& packet);

    /**
     * \brief Sets the callback to be executed when a new stream is captured.
     *
     * Whenever a new stream is captured, the provided callback will be 
     * executed.
     *
     * \param callback The callback to be set
     */
    void new_stream_callback(const stream_callback_type& callback);

    /**
     * \brief Sets the stream termination callback
     *
     * A stream is terminated when either:
     *
     * * It contains too much buffered data.
     * * No packets have been seen for some time interval.
     *
     * \param callback The callback to be executed on stream termination
     * \sa StreamFollower::stream_keep_alive
     */
    void stream_termination_callback(const stream_termination_callback_type& callback);

    /**
     * \brief Sets the maximum time a stream will be followed without capturing
     * packets that belong to it.
     *
     * \param keep_alive The maximum time to keep unseen streams
     */
    template <typename Rep, typename Period>
    void stream_keep_alive(const std::chrono::duration<Rep, Period>& keep_alive) {
        stream_keep_alive_ = keep_alive;
    }

    /**
     * Finds the stream identified by the provided arguments.
     *
     * \param client_addr The client's address
     * \param client_port The client's port
     * \param server_addr The server's address
     * \param server_addr The server's port
     */
    Stream& find_stream(const IPv4Address& client_addr, uint16_t client_port,
                        const IPv4Address& server_addr, uint16_t server_port);

    /**
     * Finds the stream identified by the provided arguments.
     *
     * \param client_addr The client's address
     * \param client_port The client's port
     * \param server_addr The server's address
     * \param server_addr The server's port
     */
    Stream& find_stream(const IPv6Address& client_addr, uint16_t client_port,
                        const IPv6Address& server_addr, uint16_t server_port);

    /**
     * \brief Indicates whether partial streams should be followed.
     *
     * Following partial streams allows capturing packets in the middle of a stream (e.g. 
     * not capturing the three way handshake) and still reassembling them.
     *
     * This can cause some issues if the first packet captured is out of order, as that would 
     * create a hole in the sequence number range that might never be filled. In order to 
     * allow recovering successfully, there's 2 choices:
     *
     * - Skipping those holes manually by using Flow::advance_sequence.
     * - Using Stream::enable_recovery_mode. This is the easiest mechanism and can be used
     * on the new stream callback (make sure to only enable it for stream for which
     * Stream::is_partial_stream is true).
     *
     * \param value Whether following partial stream is allowed.
     */
    void follow_partial_streams(bool value);
private:
    typedef Stream::timestamp_type timestamp_type;

    static const size_t DEFAULT_MAX_BUFFERED_CHUNKS;
    static const size_t DEFAULT_MAX_SACKED_INTERVALS;
    static const uint32_t DEFAULT_MAX_BUFFERED_BYTES;
    static const timestamp_type DEFAULT_KEEP_ALIVE;

    typedef std::map<stream_id, Stream> streams_type;

    Stream& find_stream(const stream_id& id);
    void process_packet(PDU& packet, const timestamp_type& ts);
    void cleanup_streams(const timestamp_type& now);

    streams_type streams_;
    stream_callback_type on_new_connection_;
    stream_termination_callback_type on_stream_termination_;
    size_t max_buffered_chunks_;
    uint32_t max_buffered_bytes_;
    timestamp_type last_cleanup_;
    timestamp_type stream_keep_alive_;
    bool attach_to_flows_;
};

} // TCPIP
} // Tins

#endif // TINS_HAVE_TCPIP

#endif // TINS_TCP_IP_STREAM_FOLLOWER_H
