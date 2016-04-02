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

#ifndef TINS_TCP_IP_STREAM_H
#define TINS_TCP_IP_STREAM_H

#include "../config.h"

#ifdef TINS_HAVE_TCPIP

#include <vector>
#include <array>
#include <map>
#include <functional>
#include <chrono>
#include <stdint.h>
#include "../macros.h"
#include "../hw_address.h"
#include "flow.h"

namespace Tins {

class PDU;
class TCP;
class IPv4Address;
class IPv6Address;

namespace TCPIP {

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
     * The type used to store payloads
     */
    typedef Flow::payload_type payload_type;

    /** 
     * The type used to represent timestamps
     */
    typedef std::chrono::microseconds timestamp_type;
    
    /**
     * The type used for callbacks
     */
    typedef std::function<void(Stream&)> stream_callback_type;

    /**
     * The type used for packet-triggered callbacks
     *
     * /sa Flow::buffering_callback
     */
    typedef std::function<void(Stream&,
                               uint32_t,
                               const payload_type&)> stream_packet_callback_type;

    /**
     * The type used to store hardware addresses
     */
    typedef HWAddress<6> hwaddress_type;


    /**
     * \brief Constructs a TCP stream using the provided packet.
     * 
     * \param initial_packet The first packet of the stream
     * \param ts The first packet's timestamp
     */
    Stream(PDU& initial_packet, const timestamp_type& ts = timestamp_type());

    /**
     * \brief Processes this packet.
     *
     * This will forward the packet appropriately to the client
     * or server flow.
     *
     * \param packet The packet to be processed
     * \param ts The packet's timestamp
     */
    void process_packet(PDU& packet, const timestamp_type& ts);

    /**
     * \brief Processes this packet.
     *
     * This will forward the packet appropriately to the client
     * or server flow.
     *
     * \param packet The packet to be processed
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
     * \brief Retrieves the client's hardware address.
     *
     * Note that this is not the actual hardware address of the client, but
     * just the address seen from packets coming from it. If the client
     * is on another network, then this will be the address of the last
     * device (switch, route, etc) the packet went through.
     */
    const hwaddress_type& client_hw_addr() const;

    /**
     * \brief Retrieves the server's hardware address.
     *
     * Note that this is not the actual hardware address of the server, but
     * just the address seen from packets coming from it. If the server
     * is on another network, then this will be the address of the last
     * device (switch, route, etc) the packet went through.
     */
    const hwaddress_type& server_hw_addr() const;

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
     * Getter for the creation time of this stream
     */
    const timestamp_type& create_time() const;

    /**
     * Getter for the last seen time of this stream
     */
    const timestamp_type& last_seen() const;

    /**
     * \brief Sets the callback to be executed when the stream is closed
     *
     * \param callback The callback to be set
     */
    void stream_closed_callback(const stream_callback_type& callback);

    /**
     * \brief Sets the callback to be executed when there's client data
     *
     * \sa Flow::data_callback
     * \param callback The callback to be set
     */
    void client_data_callback(const stream_callback_type& callback);

    /**
     * \brief Sets the callback to be executed when there's server data
     *
     * \sa Flow::data_callback
     * \param callback The callback to be set
     */
    void server_data_callback(const stream_callback_type& callback);

    /**
     * \brief Sets the callback to be executed when there's new buffered 
     * client data
     *
     * \sa Flow::buffering_callback
     * \param callback The callback to be set
     */
    void client_out_of_order_callback(const stream_packet_callback_type& callback);

    /**
     * \brief Sets the callback to be executed when there's new buffered 
     * client data
     *
     * \sa Flow::buffering_callback
     * \param callback The callback to be set
     */
    void server_out_of_order_callback(const stream_packet_callback_type& callback);

    /**
     * \brief Indicates that the data packets sent by the client should be 
     * ignored
     *
     * \sa Flow::ignore_data_packets
     */
    void ignore_client_data();

    /**
     * \brief Indicates that the data packets sent by the server should be 
     * ignored
     *
     * \sa Flow::ignore_data_packets
     */
    void ignore_server_data();

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

    /**
     * \brief Indicates whether the client flow's payloads should be 
     * automatically erased.
     *
     * \sa auto_cleanup_payloads
     */
    void auto_cleanup_client_data(bool value);

    /**
     * \brief Indicates whether the server flow's payloads should be 
     * automatically erased.
     *
     * \sa auto_cleanup_payloads
     */
    void auto_cleanup_server_data(bool value);

    /**
     * Enables tracking of acknowledged segments
     *
     * \sa Flow::enable_ack_tracking
     */
    void enable_ack_tracking();

    /**
     * \brief Indicates whether ACK number tracking is enabled for this stream
     */
    bool ack_tracking_enabled() const;
private:
    static Flow extract_client_flow(const PDU& packet);
    static Flow extract_server_flow(const PDU& packet);

    void on_client_flow_data(const Flow& flow);
    void on_server_flow_data(const Flow& flow);
    void on_client_out_of_order(const Flow& flow,
                                uint32_t seq,
                                const payload_type& payload);
    void on_server_out_of_order(const Flow& flow,
                                uint32_t seq,
                                const payload_type& payload);

    Flow client_flow_;
    Flow server_flow_;
    stream_callback_type on_stream_closed_;
    stream_callback_type on_client_data_callback_;
    stream_callback_type on_server_data_callback_;
    stream_packet_callback_type on_client_out_of_order_callback_;
    stream_packet_callback_type on_server_out_of_order_callback_;
    hwaddress_type client_hw_addr_;
    hwaddress_type server_hw_addr_;
    timestamp_type create_time_;
    timestamp_type last_seen_;
    bool auto_cleanup_client_;
    bool auto_cleanup_server_;
};

} // TCPIP
} // Tins

#endif // TINS_HAVE_TCPIP 

#endif // TINS_TCP_IP_STREAM_H
