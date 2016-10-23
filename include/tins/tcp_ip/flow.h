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

#ifndef TINS_TCP_IP_FLOW_H
#define TINS_TCP_IP_FLOW_H

#include "../config.h"

#ifdef TINS_HAVE_TCPIP

#include <vector>
#include <array>
#include <map>
#include <functional>
#include <stdint.h>
#include "../hw_address.h"
#include "../macros.h"
#include "ack_tracker.h"
#include "data_tracker.h"

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
    typedef DataTracker::payload_type payload_type;

    /**
     * The type used to store the buffered payload
     */
    typedef DataTracker::buffered_payload_type buffered_payload_type;

    /**
     * The type used to store the callback called when new data is available
     */
    typedef std::function<void(Flow&)> data_available_callback_type;

    /**
     * \brief The type used to store the callback called when data is buffered
     *
     * The arguments are the flow, the sequence number and payload that will
     * be buffered.
     */
    typedef std::function<void(Flow&,
                               uint32_t,
                               const payload_type&)> flow_packet_callback_type;

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
    void data_callback(const data_available_callback_type& callback);

    /**
     * \brief Sets the callback that will be executed when out of order data arrives
     *
     * Whenever this flow receives out-of-order data, this callback will be
     * executed.
     * 
     * \param callback The callback to be executed
     */
    void out_of_order_callback(const flow_packet_callback_type& callback);

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
     * \brief Skip forward to a sequence number
     *
     * This allows to recover from packet loss, if we just do not see all packets of
     * an original stream. This recovery can only sensibly triggered from the application
     * layer.
     *
     * This method is particularly useful to call from an out of order callback, if
     * the application wants to skip forward to this out of order block. The application
     * will then get the normal data callback!
     *
     * IMPORTANT: If you call this method with a sequence number that is not exactly a
     * TCP fragment boundary, the flow will never recover from this.
     *
     * \param seq The sequence number to skip to.
     */
    void advance_sequence(uint32_t seq);

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
     * \brief Retrieves the IPv4 destination address
     *
     * Note that it's only safe to execute this method if is_v6() == false
     */
    IPv4Address dst_addr_v4() const;

    /**
     * \brief Retrieves the IPv6 destination address
     *
     * Note that it's only safe to execute this method if is_v6() == true
     */
    IPv6Address dst_addr_v6() const;

    /** 
     * Retrieves this flow's destination port
     */
    uint16_t dport() const;

    /** 
     * Retrieves this flow's payload (const)
     */
    const payload_type& payload() const;

    /** 
     * Retrieves this flow's payload
     */
    payload_type& payload();

    /** 
     * Retrieves this flow's state
     */
    State state() const;

    /** 
     * Retrieves this flow's sequence number
     */
    uint32_t sequence_number() const;

    /** 
     * Retrieves this flow's buffered payload (const)
     */
    const buffered_payload_type& buffered_payload() const;

    /** 
     * Retrieves this flow's buffered payload
     */
    buffered_payload_type& buffered_payload();

    /**
     * Retrieves this flow's total buffered bytes
     */
    uint32_t total_buffered_bytes() const;

    /**
     * Sets the state of this flow
     *
     * \param new_state The new state of this flow
     */
    void state(State new_state);

    /**
     * \brief Sets whether this flow should ignore data packets
     *
     * If the data packets are ignored then the flow will just be 
     * followed to keep track of its state.
     */
    void ignore_data_packets();

    /**
     * \brief Returns the MSS for this Flow.
     *
     * If the MSS option wasn't provided by the peer, -1 is returned
     */
    int mss() const;

    /**
     * \brief Indicates whether this Flow supports selective acknowledgements
     */
    bool sack_permitted() const;

    /** 
     * \brief Enables tracking of ACK numbers
     *
     * This requires having the boost.icl library. If the library is not installed
     * or ACK tracking was disabled when compiling the library, then this method
     * will throw an exception.
     */
    void enable_ack_tracking();

    /**
     * \brief Indicates whether ACK number tracking is enabled
     */
    bool ack_tracking_enabled() const;

    #ifdef TINS_HAVE_ACK_TRACKER
    /**
     * Retrieves the ACK tracker for this Flow (const)
     */
    const AckTracker& ack_tracker() const;

    /**
     * Retrieves the ACK tracker for this Flow
     */
    AckTracker& ack_tracker();
    #endif // TINS_HAVE_ACK_TRACKER
private:
    // Compress all flags into just one struct using bitfields 
    struct flags {
        flags() : is_v6(0), ignore_data_packets(0), sack_permitted(0), ack_tracking(0) {

        }

        uint32_t is_v6:1,
                 ignore_data_packets:1,
                 sack_permitted:1,
                 ack_tracking:1;
    };

    void update_state(const TCP& tcp);
    void initialize();

    DataTracker data_tracker_;
    std::array<uint8_t, 16> dest_address_;
    uint16_t dest_port_;
    data_available_callback_type on_data_callback_;
    flow_packet_callback_type on_out_of_order_callback_;
    State state_;
    int mss_;
    flags flags_;
    #ifdef TINS_HAVE_ACK_TRACKER
    AckTracker ack_tracker_;
    #endif // TINS_HAVE_ACK_TRACKER
};

} // TCPIP
} // TINS

#endif // TINS_HAVE_TCPIP
#endif // TINS_TCP_IP_FLOW_H

