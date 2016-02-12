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

#include "../cxxstd.h"

// This classes use C++11 features
#if TINS_IS_CXX11

#include <map>
#include "stream.h"

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
     * \brief The type used for callbacks
     */
    typedef Stream::stream_callback_type stream_callback_type;

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
    Stream& find_stream(IPv4Address client_addr, uint16_t client_port,
                        IPv4Address server_addr, uint16_t server_port);

    /**
     * Finds the stream identified by the provided arguments.
     *
     * \param client_addr The client's address
     * \param client_port The client's port
     * \param server_addr The server's address
     * \param server_addr The server's port
     */
    Stream& find_stream(IPv6Address client_addr, uint16_t client_port,
                        IPv6Address server_addr, uint16_t server_port);
private:
    typedef std::array<uint8_t, 16> address_type;
    typedef Stream::timestamp_type timestamp_type;

    static const size_t DEFAULT_MAX_BUFFERED_CHUNKS;
    static const timestamp_type DEFAULT_CLEANUP_INTERVAL;
    static const timestamp_type DEFAULT_KEEP_ALIVE;

    struct stream_id {
        stream_id(const address_type& client_addr, uint16_t client_port,
                  const address_type& server_addr, uint16_t server_port);

        address_type min_address;
        address_type max_address;
        uint16_t min_address_port;
        uint16_t max_address_port;

        bool operator<(const stream_id& rhs) const;

        static size_t hash(const stream_id& id);
    };

    typedef std::map<stream_id, Stream> streams_type;

    stream_id make_stream_id(const PDU& packet);
    Stream& find_stream(const stream_id& id);
    static address_type serialize(IPv4Address address);
    static address_type serialize(const IPv6Address& address);
    void process_packet(PDU& packet, const timestamp_type& ts);
    void cleanup_streams(const timestamp_type& now);

    streams_type streams_;
    stream_callback_type on_new_connection_;
    size_t max_buffered_chunks_;
    timestamp_type last_cleanup_;
    timestamp_type stream_keep_alive_;
    bool attach_to_flows_;
};

} // TCPIP
} // Tins

#endif // TINS_IS_CXX11

#endif // TINS_TCP_IP_STREAM_FOLLOWER_H
