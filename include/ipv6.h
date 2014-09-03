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

#ifndef TINS_IPV6_h
#define TINS_IPV6_h

#include <list>
#include <stdexcept>
#include "macros.h"
#include "pdu.h"
#include "endianness.h"
#include "small_uint.h"
#include "pdu_option.h"
#include "ipv6_address.h"

namespace Tins {
class PacketSender;
    
/**
 * \class IPv6
 * Represents an IPv6 PDU.
 */
class IPv6 : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::IPv6;
    
    /**
     * The type used to store addresses.
     */
    typedef IPv6Address address_type;
    
    /**
     * The type used to represent IPv6 extension headers.
     */
    typedef PDUOption<uint8_t, IPv6> ext_header;
    
    /**
     * The type used to store the extension headers.
     */
    typedef std::list<ext_header> headers_type;

    /**
     * The values used to identify extension headers.
     */
    enum ExtensionHeader {
        HOP_BY_HOP = 0,
        DESTINATION_ROUTING_OPTIONS = 60,
        ROUTING = 43,
        FRAGMENT = 44,
        AUTHENTICATION = 51,
        SECURITY_ENCAPSULATION = 50,
        DESTINATION_OPTIONS = 60,
        MOBILITY = 135,
        NO_NEXT_HEADER = 59
    };

    /**
     * \brief Constructs an IPv6 object.
     * 
     * \param ip_dst The destination ip address(optional).
     * \param ip_src The source ip address(optional).
     * \param child pointer to a PDU which will be set as the inner_pdu 
     * for the packet being constructed(optional).
     */
    IPv6(address_type ip_dst = address_type(), 
        address_type ip_src = address_type(), 
        PDU *child = 0);

    /**
     * \brief Constructs an IPv6 object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this one.
     * 
     * If there is not enough size for an IPv6 header, a malformed_packet
     * exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    IPv6(const uint8_t *buffer, uint32_t total_sz);

    // Getters

    /**
     * \brief Getter for the version field.
     *  \return The stored version field value.
     */
    small_uint<4> version() const {
        return _header.version;
    }

    /**
     * \brief Getter for the traffic_class field.
     *  \return The stored traffic_class field value.
     */
    uint8_t traffic_class() const {
        #if TINS_IS_LITTLE_ENDIAN
        return ((_header.traffic_class << 4) & 0xf0) | 
                ((_header.flow_label[0] >> 4) & 0x0f);
        #else
        return _header.traffic_class;
        #endif
    }

    /**
     * \brief Getter for the flow_label field.
     *  \return The stored flow_label field value.
     */
    small_uint<20> flow_label() const {
        #if TINS_IS_LITTLE_ENDIAN
        return ((_header.flow_label[0] & 0x0f) << 16)
                | (_header.flow_label[1] << 8)
                | (_header.flow_label[2]);
        #else
        return _header.flow_label;
        #endif
    }

    /**
     * \brief Getter for the payload_length field.
     *  \return The stored payload_length field value.
     */
    uint16_t payload_length() const {
        return Endian::be_to_host(_header.payload_length);
    }

    /**
     * \brief Getter for the next_header field.
     *  \return The stored next_header field value.
     */
    uint8_t next_header() const {
        return _header.next_header;
    }

    /**
     * \brief Getter for the hop_limit field.
     *  \return The stored hop_limit field value.
     */
    uint8_t hop_limit() const {
        return _header.hop_limit;
    }

    /**
     * \brief Getter for the src_addr field.
     *  \return The stored src_addr field value.
     */
    address_type src_addr() const {
        return _header.src_addr;
    }

    /**
     * \brief Getter for the dst_addr field.
     *  \return The stored dst_addr field value.
     */
    address_type dst_addr() const {
        return _header.dst_addr;
    }

    /**
     * \brief Getter for the IPv6 extension headers.
     *  \return The stored headers.
     */
    const headers_type& headers() const {
        return ext_headers;
    }

    // Setters

    /**
     * \brief Setter for the version field.
     * \param new_version The new version field value.
     */
    void version(small_uint<4> new_version);

    /**
     * \brief Setter for the traffic_class field.
     * \param new_traffic_class The new traffic_class field value.
     */
    void traffic_class(uint8_t new_traffic_class);

    /**
     * \brief Setter for the flow_label field.
     * \param new_flow_label The new flow_label field value.
     */
    void flow_label(small_uint<20> new_flow_label);

    /**
     * \brief Setter for the payload_length field.
     * \param new_payload_length The new payload_length field value.
     */
    void payload_length(uint16_t new_payload_length);

    /**
     * \brief Setter for the next_header field.
     * \param new_next_header The new next_header field value.
     */
    void next_header(uint8_t new_next_header);

    /**
     * \brief Setter for the hop_limit field.
     * \param new_hop_limit The new hop_limit field value.
     */
    void hop_limit(uint8_t new_hop_limit);

    /**
     * \brief Setter for the src_addr field.
     * \param new_src_addr The new src_addr field value.
     */
    void src_addr(const address_type &new_src_addr);

    /**
     * \brief Setter for the dst_addr field.
     * \param new_dst_addr The new dst_addr field value.
     */
    void dst_addr(const address_type &new_dst_addr);
    
    /**
     * \brief Returns the header size.
     *
     * This metod overrides PDU::header_size. \sa PDU::header_size
     */
    uint32_t header_size() const;
    
    /** 
     * \brief Check wether ptr points to a valid response for this PDU.
     *
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t *ptr, uint32_t total_sz) const;
    
    /**
     * \sa PDU::clone
     */
    IPv6 *clone() const {
        return new IPv6(*this);
    }
    
    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }
    
    #ifndef BSD
    /**
     * \sa PDU::send()
     */
    void send(PacketSender &sender, const NetworkInterface &);
    #endif
    
    /**
     * Adds an extension header.
     * 
     * \param header The extension header to be added.
     */
    void add_ext_header(const ext_header &header);
    
    /**
     * \brief Searchs for an extension header that matchs the given 
     * flag.
     * 
     * If the header is not found, a null pointer is returned. 
     * Deleting the returned pointer will result in <b>undefined 
     * behaviour</b>.
     * 
     * \param id The header identifier to be searched.
     */
    const ext_header *search_header(ExtensionHeader id) const;
private:
    void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
    void set_last_next_header(uint8_t value);
    static uint8_t *write_header(const ext_header &header, uint8_t *buffer);
    static bool is_extension_header(uint8_t header_id);

    TINS_BEGIN_PACK
    struct ipv6_header {
        #if TINS_IS_BIG_ENDIAN
        uint32_t version:4,
                traffic_class:8,
                flow_label:20;
        uint32_t payload_length:16,
                next_header:8,
                hop_limit:8;
        #else
        uint8_t traffic_class:4,
                version:4;
        uint8_t flow_label[3];
        uint16_t payload_length;
        uint8_t next_header;
        uint8_t hop_limit;
        #endif
        uint8_t src_addr[16], dst_addr[16];
    } TINS_END_PACK;

    ipv6_header _header;
    headers_type ext_headers;
    uint32_t headers_size;
};
}

#endif // TINS_IPV6_h
