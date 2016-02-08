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

#ifndef TINS_TCP_IP_H
#define TINS_TCP_IP_H

#include "cxxstd.h"

// This classes use C++11 features
#if TINS_IS_CXX11

#include <vector>
#include <array>
#include <map>
#include <functional>
#include <stdint.h>
#include "macros.h"

namespace Tins {

class PDU;
class TCP;
class IPv4Address;
class IPv6Address;

namespace TCPIP {

/**
 * \brief Represents an unidirectional TCP flow between 2 endpoints
 *
 * This class will keep the state for all the traffic sent by
 * one of the peers in a TCP connection. This contains the sequence number,
 * payload ready to be read and buffered payload, along with some other
 * properties of the flow.
 *
 * A TCP stream (see class Stream) is made out of 2 Flows, so you should 
 * probably have a look at that class first.
 *
 * You shouldn't normally need to interact with this class. Stream already
 * provides proxys to most of its Flow's attributes.
 */
class TINS_API Flow {
public:
    /**
     * \brief Enum that indicates the state of this flow.
     * 
     * Note that although similar, this is not mapped to a TCP state-machine 
     * state. This is mostly used internally to know which packets the flow is
     * expecting and to know when it's done sending data.
     */
    enum State {
        UNKNOWN,
        SYN_SENT,
        ESTABLISHED,
        FIN_SENT,
        RST_SENT
    };

    /** 
     * The type used to store the payload
     */
    typedef std::vector<uint8_t> payload_type;

    /**
     * The type used to store the buffered payload
     */
    typedef std::map<uint32_t, payload_type> buffered_payload_type;

    /**
     * The type used to store the callbacks that this class triggers
     */
    typedef std::function<void(Flow&)> event_callback;

    /** 
     * Construct a Flow from an IPv4 address
     *
     * \param dst_address This flow's destination address
     * \param dst_port This flow's destination port
     * \param sequence_number The initial sequence number to be used 
     */
    Flow(const IPv4Address& dst_address, uint16_t dst_port,
         uint32_t sequence_number);
    
    /** 
     * Construct a Flow from an IPv6 address
     *
     * \param dst_address This flow's destination address
     * \param dst_port This flow's destination port
     * \param sequence_number The initial sequence number to be used 
     */
    Flow(const IPv6Address& dst_address, uint16_t dst_port,
         uint32_t sequence_number);

    /**
     * \brief Sets the callback that will be executed when data is readable
     *
     * Whenever this flow has readable data, this callback will be executed.
     * By readable, this means that there's non-out-of-order data captured.
     *
     * \param callback The callback to be executed   
     */
    void data_callback(const event_callback& callback);

    /**
     * \brief Sets the callback that will be executed when data is buffered.
     *
     * Whenever this flow receives out-of-order data, this callback will be
     * executed.
     * 
     * \param callback The callback to be executed
     */
    void buffering_callback(const event_callback& callback);

    /**
     * \brief Processes a packet.
     *
     * If this packet contains data and starts or overlaps with the current
     * sequence number, then the data will be appended to this flow's payload
     * and the data_callback will be executed.
     *
     * If this packet contains out-of-order data, it will be buffered and the
     * buffering_callback will be executed.
     *
     * \param pdu The packet to be processed
     * \sa Flow::data_callback
     * \sa Flow::buffering_callback
     */
    void process_packet(PDU& pdu);

    /**
     * Indicates whether this flow uses IPv6 addresses
     */
    bool is_v6() const;

    /**
     * \brief Indicates whether this flow is finished
     *
     * A finished is considered to be finished if either it sent a
     * packet with the FIN or RST flags on. 
     */
    bool is_finished() const;

    /**
     * \brief Indicates whether a packet belongs to this flow
     *
     * Since Flow represents a unidirectional stream, this will only check
     * the destination endpoint and not the source one.
     *
     * \param packet The packet to be checked
     */
    bool packet_belongs(const PDU& packet) const;

    /**
     * \brief Getter for the IPv4 destination address
     *
     * Note that it's only safe to execute this method if is_v6() == false
     */
    IPv4Address dst_addr_v4() const;

    /**
     * \brief Getter for the IPv6 destination address
     *
     * Note that it's only safe to execute this method if is_v6() == true
     */
    IPv6Address dst_addr_v6() const;

    /** 
     * Getter for this flow's destination port
     */
    uint16_t dport() const;

    /** 
     * Getter for this flow's payload (const)
     */
    const payload_type& payload() const;

    /** 
     * Getter for this flow's destination port
     */
    payload_type& payload();

    /** 
     * Getter for this flow's state
     */
    State state() const;

    /** 
     * Getter for this flow's sequence number
     */
    uint32_t sequence_number() const;

    /** 
     * Getter for this flow's buffered payload (const)
     */
    const buffered_payload_type& buffered_payload() const;

    /** 
     * Getter for this flow's buffered payload
     */
    buffered_payload_type& buffered_payload();

    /**
     * Sets the state of this flow
     *
     * \param new_state The new state of this flow
     */
    void state(State new_state);
private:
    void store_payload(uint32_t seq, const payload_type& payload);
    buffered_payload_type::iterator erase_iterator(buffered_payload_type::iterator iter);
    void update_state(const TCP& tcp);

    payload_type payload_;
    buffered_payload_type buffered_payload_;
    uint32_t seq_number_;
    std::array<uint8_t, 16> dest_address_;
    uint16_t dest_port_;
    event_callback on_data_callback_;
    event_callback on_buffering_callback_;
    State state_;
    bool is_v6_;
};

/** 
 * \brief Represents a TCP stream
 *
 * A TCP stream is made out of 2 Flows, one in each direction, plus 
 * some other attributes and callbacks.
 *
 * This class works using callbacks. Whenever the stream is created, you should
 * set at least the client/server callbacks so you are notified whenever the
 * client/server has sent data. Note that setting these is not mandatory, so
 * you can subscribe to just the callbacks you need.
 *
 * \sa Stream::auto_cleanup_payloads
 */
class TINS_API Stream {
public:
    /**
     * The type used for callbacks
     */
    typedef std::function<void(Stream&)> stream_callback;

    /**
     * The type used to store payloads
     */
    typedef Flow::payload_type payload_type;

    /**
     * \brief Constructs a TCP stream using the provided packet.
     */
    Stream(const PDU& initial_packet);

    /**
     * \brief Processes this packet.
     *
     * This will forward the packet appropriately to the client
     * or server flow.
     */
    void process_packet(PDU& packet);

    /**
     * Getter for the client flow
     */
    Flow& client_flow();

    /**
     * Getter for the client flow (const)
     */
    const Flow& client_flow() const;

    /**
     * Getter for the server flow
     */
    Flow& server_flow();

    /**
     * Getter for the server flow (const)
     */
    const Flow& server_flow() const;

    /**
     * \brief Indicates whether this stream is finished.
     *
     * This stream is finished if either peer sent a packet with
     * the RST flag on, or both peers sent a FIN.
     */
    bool is_finished() const;

    /**
     * Indicates whether this packet uses IPv6 addresses
     */
    bool is_v6() const;

    /**
     * \brief Retrieves the client's IPv4 address
     *
     * Note that it's only valid to call this method if is_v6() == false
     */
    IPv4Address client_addr_v4() const;

    /**
     * \brief Retrieves the client's IPv6 address
     *
     * Note that it's only valid to call this method if is_v6() == true
     */
    IPv6Address client_addr_v6() const;

    /**
     * \brief Retrieves the server's IPv4 address
     *
     * Note that it's only valid to call this method if is_v6() == false
     */
    IPv4Address server_addr_v4() const;

    /**
     * \brief Retrieves the server's IPv6 address
     *
     * Note that it's only valid to call this method if is_v6() == true
     */
    IPv6Address server_addr_v6() const;

    /**
     * Getter for the client's port
     */
    uint16_t client_port() const;

    /**
     * Getter for the server's port
     */
    uint16_t server_port() const;

    /**
     * Getter for the client's payload (const)
     */
    const payload_type& client_payload() const;

    /**
     * Getter for the client's payload
     */
    payload_type& client_payload();

    /**
     * Getter for the server's payload (const)
     */
    const payload_type& server_payload() const;

    /**
     * Getter for the server's payload
     */
    payload_type& server_payload();

    /**
     * \brief Sets the callback to be executed when the stream is closed
     *
     * \param callback The callback to be set
     */
    void stream_closed_callback(const stream_callback& callback);

    /**
     * \brief Sets the callback to be executed when there's client data
     *
     * \sa Flow::data_callback
     * \param callback The callback to be set
     */
    void client_data_callback(const stream_callback& callback);

    /**
     * \brief Sets the callback to be executed when there's server data
     *
     * \sa Flow::data_callback
     * \param callback The callback to be set
     */
    void server_data_callback(const stream_callback& callback);

    /**
     * \brief Sets the callback to be executed when there's new buffered 
     * client data
     *
     * \sa Flow::buffering_callback
     * \param callback The callback to be set
     */
    void client_buffering_callback(const stream_callback& callback);

    /**
     * \brief Sets the callback to be executed when there's new buffered 
     * client data
     *
     * \sa Flow::buffering_callback
     * \param callback The callback to be set
     */
    void server_buffering_callback(const stream_callback& callback);

    /**
     * \brief Sets the internal callbacks. 
     *
     * This shouldn't normally need to be called except if you're constructing
     * this object and then moving it around before persisting it somewhere.  
     */
    void setup_flows_callbacks();

    /**
     * \brief Indicates whether each flow's payloads should be automatically
     * erased.
     *
     * If this property is true, then whenever there's new data for a stream,
     * the appropriate callback will be executed and then the payload will be 
     * erased. 
     *
     * If this property is false, then the payload <b>will not</b> be erased
     * and the user is responsible for clearing the payload vector. 
     *
     * Setting this property to false is useful if it's desired to hold all 
     * of the data sent on the stream before processing it. Note that this
     * can lead to the memory growing a lot.
     *
     * This property is true by default. 
     *
     * \param value The value to be set for this property
     */
    void auto_cleanup_payloads(bool value);
private:
    static Flow extract_client_flow(const PDU& packet);
    static Flow extract_server_flow(const PDU& packet);

    void on_client_flow_data(const Flow& flow);
    void on_server_flow_data(const Flow& flow);
    void on_client_buffering(const Flow& flow);
    void on_server_buffering(const Flow& flow);

    Flow client_flow_;
    Flow server_flow_;
    stream_callback on_stream_closed_;
    stream_callback on_client_data_callback_;
    stream_callback on_server_data_callback_;
    stream_callback on_client_buffering_callback_;
    stream_callback on_server_buffering_callback_;
    bool auto_cleanup_;
};

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
    typedef Stream::stream_callback stream_callback;

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
     * This method always returns true so it can be easily plugged as
     * the argument to Sniffer::sniff_loop.
     *
     * \param packet The packet to be processed
     * \return Always true
     */
    bool process_packet(PDU& packet);

    /**
     * \brief Sets the callback to be executed when a new stream is captured.
     *
     * Whenever a new stream is captured, the provided callback will be 
     * executed.
     *
     * \param callback The callback to be set
     */
    void new_stream_callback(const stream_callback& callback);

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
    static const size_t DEFAULT_MAX_BUFFERED_CHUNKS;
    typedef std::array<uint8_t, 16> address_type;

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

    streams_type streams_;
    stream_callback on_new_connection_;
    size_t max_buffered_chunks_;
    bool attach_to_flows_;
};

} // TCPIP
} // Tins

#endif // TINS_IS_CXX11 

#endif // TINS_TCP_IP_H
