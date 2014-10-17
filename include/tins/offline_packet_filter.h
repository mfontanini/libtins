/*
 * Copyright (c) 2014, Matias Fontanini
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

#ifndef TINS_OFFLINE_PACKET_FILTER_H
#define TINS_OFFLINE_PACKET_FILTER_H

#include <string>
#include <stdint.h>
#include "data_link_type.h"

namespace Tins {
class PDU;

/**
 * \class OfflinePacketFilter
 *
 * \brief Wraps a pcap filter and matches it against a packet or buffer.
 *
 * This is a thin wrapper over <i>pcap_offline_filter</i>. You can use
 * it to perform packet filtering outside of Sniffer instances. 
 *
 * A potential use case would be if you are capturing packets that are
 * sent from another host over UDP. You would recieve UDP packets, then
 * parse their content, and apply the OfflinePacketFilter over the
 * wrapped packet. For example:
 *
 * \code
 * // Assume we get an UDP packet from somewhere.
 * // Inside the payload, there will be a complete packet
 * // including its link layer protocol.
 * UDP udp = get_packet();
 *
 * // Create the filter. We'll be expecting Ethernet packets.
 * OfflinePacketFilter filter("ip and port 80", DataLinkLayer<EthernetII>());
 * 
 * // We can use this directly over the inner PDU (assuming it has one)
 * // See the notes on the efficiency of doing it this way.
 * if(filter.matches_filter(*udp.inner_pdu())) {
 *     // Matches!
 * }
 *
 * // We can also use the payload. This version it faster and should
 * // be preferred over the one above
 * const RawPDU& raw = udp.rfind_pdu<RawPDU>();
 * const auto& payload = raw.payload();
 * if(filter.matches_filter(payload.data(), payload.size())) {
 *     // Matches!
 * }
 * \endcode
 */
class OfflinePacketFilter {
public:
    /**
     * Constructs an OfflinePacketFilter object.
     *
     * \param filter The pcap filter to use.
     * \param lt The link layer type to use.
     * \param snap_len The snapshot length to use.
     */
    template<typename T>
    OfflinePacketFilter(const std::string& filter, const DataLinkType<T>& lt,
        unsigned int snap_len = 65535)
    : string_filter(filter)
    {
        init(filter, lt.get_type(), snap_len);
    }

    /**
     * \brief Copy constructor.
     *
     * Note that during copy construction the pcap filter is 
     * recompiled. Therefore, it might be somehow expensive to
     * copy OfflinePacketFilters.
     *
     * \param other The filter to be copied.
     */
    OfflinePacketFilter(const OfflinePacketFilter& other);

    /**
     * \brief Copy assignment operator.
     *
     * \param other The filter to be copied.
     * 
     * \sa OfflinePacketFilter
     */
    OfflinePacketFilter& operator=(const OfflinePacketFilter& other);

    /**
     * Releases the compiled pcap filter and handle.
     */
    ~OfflinePacketFilter();

    /**
     * \brief Applies the compiled filter on the provided buffer.
     *
     * This method uses <i>pcap_offline_filter</i> on the provided buffer
     * and returns a bool indicating if the packet pointed by the buffer
     * matches the filter.
     *
     * \param buffer A pointer to a buffer which holds a raw packet.
     * \param total_sz The length of the buffer pointed by buffer.
     * \return true iff the packet matches the filter.
     */
     bool matches_filter(const uint8_t* buffer, uint32_t total_sz) const;

     /**
      * \brief Applies the compiled filter on the provided packet.
      *
      * This method checks whether the provided packet matches the filter.
      * Since this uses pcap filters and they work over a raw data buffer,
      * this method serialices the packet and then applies the filter. 
      * Therefore, this can be quite expensive to use. If you have access
      * to the packet before constructing a PDU from it, it is recommended
      * to use the other overload over the raw buffer.
      *
      * \param pdu The packet to be matched against the filter.
      * \return true iff the packet matches the filter.
      */
     bool matches_filter(PDU& pdu) const;
private:
    void init(const std::string& pcap_filter, int link_type, 
        unsigned int snap_len);


    pcap_t* handle;
    mutable bpf_program filter;
    std::string string_filter;
};
} // Tins

#endif // TINS_OFFLINE_PACKET_FILTER_H
