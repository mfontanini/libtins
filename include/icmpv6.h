/*
 * Copyright (c) 2012, Nasel
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
 
#ifndef TINS_ICMPV6_H
#define TINS_ICMPV6_H

#include <list>
#include "pdu.h"
#include "ipv6_address.h"
#include "pdu_option.h"
#include "endianness.h"
#include "small_uint.h"

namespace Tins {
/**
 * Represents an ICMPv6 PDU.
 */
class ICMPv6 : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::ICMPv6;
    
    /**
     * The types of ICMPv6 messages
     */
    enum Types {
        DEST_UNREACHABLE = 1,
        PACKET_TOOBIG = 2,
        TIME_EXCEEDED = 3,
        PARAM_PROBLEM = 4,
        ECHO_REQUEST = 128,
        ECHO_REPLY = 129,
        MGM_QUERY = 130,
        MGM_REPORT = 131,
        MGM_REDUCTION = 132,
        ROUTER_SOLICIT = 133,
        ROUTER_ADVERT = 134,
        NEIGHBOUR_SOLICIT = 135,
        NEIGHBOUR_ADVERT = 136,
        REDIRECT = 137,
        ROUTER_RENUMBER = 137,
        NI_QUERY = 139,
        NI_REPLY = 140,
        MLD2_REPORT = 143,
        DHAAD_REQUEST = 144,
        DHAAD_REPLY = 145,
        MOBILE_PREFIX_SOL = 146,
        MOBILE_PREFIX_ADV = 147
    };
    
    /**
     * The types of ICMPv6 options.
     */
    enum Options {
        SOURCE_ADDRESS = 1,
        TARGET_ADDRESS,
        PREFIX_INFO,
        REDIRECT_HEADER,
        MTU,
        NBMA_SHORT_LIMIT,
        ADVERT_INTERVAL,
        HOME_AGENT_INFO,
        S_ADDRESS_LIST,
        T_ADDRESS_LIST,
        CGA,
        RSA_SIGN,
        TIMESTAMP,
        NONCE,
        TRUST_ANCHOR,
        CERTIFICATE,
        IP_PREFIX,
        NEW_ROUTER_PREFIX,
        LINK_ADDRESS,
        NEIGHBOUR_ADVERT_ACK,
        MAP = 23,
        ROUTE_INFO,
        RECURSIVE_DNS_SERV,
        RA_FLAGS_EXT,
        HANDOVER_KEY_REQ,
        HANDOVER_KEY_REPLY,
        HANDOVER_ASSIST_INFO,
        MOBILE_NODE_ID,
        DNS_SEARCH_LIST,
        PROXY_SIGNATURE,
        ADDRESS_REG,
        SIXLOWPAN_CONTEXT,
        AUTHORITATIVE_BORDER_ROUTER,
        CARD_REQUEST = 138,
        CARD_REPLY
    };
    
    /**
     * The type used to store addresses.
     */
    typedef IPv6Address address_type;
    
    /**
     * The type used to represent ICMPv6 options.
     */
    typedef PDUOption<uint8_t> icmpv6_option;
    
    /**
     * The type used to store options.
     */
    typedef std::list<icmpv6_option> options_type;
    
    /**
     * \brief Constructs an ICMPv6 object.
     * 
     * The type of the constructed object will be an echo request, unless
     * you provide another one in the tp parameter.
     * 
     * \param tp The message type of this ICMPv6 object.
     */
    ICMPv6(Types tp = ECHO_REQUEST);
    
    /**
     * \brief Constructor which creates an ICMP object from a buffer and 
     * adds all identifiable PDUs found in the buffer as children of this one.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    ICMPv6(const uint8_t *buffer, uint32_t total_sz);
    
    // Getters

    /**
     *  \brief Getter for the type field.
     *  \return The stored type field value.
     */
    Types type() const {
        return static_cast<Types>(_header.type);
    }

    /**
     *  \brief Getter for the code field.
     *  \return The stored code field value.
     */
    uint8_t code() const {
        return _header.code;
    }

    /**
     *  \brief Getter for the cksum field.
     *  \return The stored cksum field value.
     */
    uint16_t checksum() const {
        return Endian::be_to_host(_header.cksum);
    }

    /**
     *  \brief Getter for the identifier field.
     *  \return The stored identifier field value.
     */
    uint16_t identifier() const {
        return Endian::be_to_host(_header.u_echo.identifier);
    }

    /**
     *  \brief Getter for the sequence field.
     *  \return The stored sequence field value.
     */
    uint16_t sequence() const {
        return Endian::be_to_host(_header.u_echo.sequence);
    }

    /**
     *  \brief Getter for the override field.
     *  \return The stored override field value.
     */
    small_uint<1> override() const {
        return _header.u_nd_advt.override;
    }

    /**
     *  \brief Getter for the solicited field.
     *  \return The stored solicited field value.
     */
    small_uint<1> solicited() const {
        return _header.u_nd_advt.solicited;
    }

    /**
     *  \brief Getter for the router field.
     *  \return The stored router field value.
     */
    small_uint<1> router() const {
        return _header.u_nd_advt.router;
    }

    /**
     *  \brief Getter for the hop_limit field.
     *  \return The stored hop_limit field value.
     */
    uint8_t hop_limit() const {
        return _header.u_nd_ra.hop_limit;
    }

    /**
     *  \brief Getter for the router_pref field.
     *  \return The stored router_pref field value.
     */
    small_uint<2> router_pref() const {
        return _header.u_nd_ra.router_pref;
    }

    /**
     *  \brief Getter for the home_agent field.
     *  \return The stored home_agent field value.
     */
    small_uint<1> home_agent() const {
        return _header.u_nd_ra.home_agent;
    }

    /**
     *  \brief Getter for the other field.
     *  \return The stored other field value.
     */
    small_uint<1> other() const {
        return _header.u_nd_ra.other;
    }

    /**
     *  \brief Getter for the managed field.
     *  \return The stored managed field value.
     */
    small_uint<1> managed() const {
        return _header.u_nd_ra.managed;
    }

    /**
     *  \brief Getter for the router_lifetime field.
     *  \return The stored router_lifetime field value.
     */
    uint16_t router_lifetime() const {
        return Endian::be_to_host(_header.u_nd_ra.router_lifetime);
    }
    
    /**
     *  \brief Getter for the reachable_time field.
     *  \return The stored reachable_time field value.
     */
    uint32_t reachable_time() const {
        return Endian::be_to_host(reach_time);
    }
    
    /**
     *  \brief Getter for the retransmit_timer field.
     *  \return The stored retransmit_timer field value.
     */
    uint32_t retransmit_timer() const {
        return Endian::be_to_host(retrans_timer);
    }
    
    /**
     *  \brief Getter for the target address field.
     *  \return The stored target address field value.
     */
    const address_type &target_addr() const {
        return _target_address;
    }

    // Setters

    /**
     *  \brief Setter for the type field.
     *  \param new_type The new type field value.
     */
    void type(Types new_type);

    /**
     *  \brief Setter for the code field.
     *  \param new_code The new code field value.
     */
    void code(uint8_t new_code);

    /**
     *  \brief Setter for the cksum field.
     *  \param new_cksum The new cksum field value.
     */
    void checksum(uint16_t new_cksum);

    /**
     *  \brief Setter for the identifier field.
     *  \param new_identifier The new identifier field value.
     */
    void identifier(uint16_t new_identifier);

    /**
     *  \brief Setter for the sequence field.
     *  \param new_sequence The new sequence field value.
     */
    void sequence(uint16_t new_sequence);

    /**
     *  \brief Setter for the override field.
     *  \param new_override The new override field value.
     */
    void override(small_uint<1> new_override);

    /**
     *  \brief Setter for the solicited field.
     *  \param new_solicited The new solicited field value.
     */
    void solicited(small_uint<1> new_solicited);

    /**
     *  \brief Setter for the router field.
     *  \param new_router The new router field value.
     */
    void router(small_uint<1> new_router);

    /**
     *  \brief Setter for the hop_limit field.
     *  \param new_hop_limit The new hop_limit field value.
     */
    void hop_limit(uint8_t new_hop_limit);

    /**
     *  \brief Setter for the router_pref field.
     *  \param new_router_pref The new router_pref field value.
     */
    void router_pref(small_uint<2> new_router_pref);

    /**
     *  \brief Setter for the home_agent field.
     *  \param new_home_agent The new home_agent field value.
     */
    void home_agent(small_uint<1> new_home_agent);

    /**
     *  \brief Setter for the other field.
     *  \param new_other The new other field value.
     */
    void other(small_uint<1> new_other);

    /**
     *  \brief Setter for the managed field.
     *  \param new_managed The new managed field value.
     */
    void managed(small_uint<1> new_managed);

    /**
     *  \brief Setter for the router_lifetime field.
     *  \param new_router_lifetime The new router_lifetime field value.
     */
    void router_lifetime(uint16_t new_router_lifetime);
    
    /**
     *  \brief Setter for the target address field.
     *  \param new_target_addr The new target address field value.
     */
    void target_addr(const address_type &new_target_addr);

    /**
     *  \brief Setter for the reachable_time field.
     *  \param new_reachable_time The new reachable_time field value.
     */
    void reachable_time(uint32_t new_reachable_time);
    
    /**
     *  \brief Setter for the retransmit_timer field.
     *  \param new_retrans_timer The new retrans_timer field value.
     */
    void retransmit_timer(uint32_t new_retrans_timer);

    /**
     * \brief Getter for the PDU's type.
     *
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Checks whether this ICMPv6 object has a target_addr field.
     * 
     * This depends on the type field.
     */
    bool has_target_addr() const {
        return type() == NEIGHBOUR_SOLICIT || 
                type() == NEIGHBOUR_ADVERT || 
                type() == REDIRECT;
    }
    
    /**
     * \brief Adds an ICMPv6 option.
     * 
     * The option is added after the last option in the option 
     * fields.
     * 
     * \param option The option to be added
     */
    void add_option(const icmpv6_option &option);

    /**
     * \brief Returns the header size.
     *
     * This metod overrides PDU::header_size. This size includes the
     * payload and options size. \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Searchs for an option that matchs the given flag.
     * 
     * If the header is not found, a null pointer is returned. 
     * Deleting the returned pointer will result in <b>undefined 
     * behaviour</b>.
     * 
     * \param id The option identifier to be searched.
     */
    const icmpv6_option *search_option(Options id) const;

    /**
     * \sa PDU::clone
     */
    ICMPv6 *clone() const {
        return new ICMPv6(*this);
    }
private:
    struct icmp6hdr {
        uint8_t	type;
        uint8_t code;
        uint16_t cksum;
        union {
            struct {
                uint16_t identifier;
                uint16_t sequence;
            } u_echo;
            
            struct {
        #if TINS_IS_LITTLE_ENDIAN
            uint32_t reserved:5,
                        override:1,
                        solicited:1,
                        router:1,
                        reserved2:24;
        #else
            uint32_t router:1,
                        solicited:1,
                        override:1,
                        reserved:29;
        #endif						
            } u_nd_advt;
            struct {
                uint8_t	hop_limit;
        #if TINS_IS_LITTLE_ENDIAN
                uint8_t reserved:3,
                        router_pref:2,
                        home_agent:1,
                        other:1,
                        managed:1;
        #else
                uint8_t managed:1,
                        other:1,
                        home_agent:1,
                        router_pref:2,
                        reserved:3;
        #endif
                uint16_t router_lifetime;
            } u_nd_ra;
        };
    } __attribute__((packed));
    
    void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
    bool has_options() const;
    uint8_t *write_option(const icmpv6_option &opt, uint8_t *buffer);
    void parse_options(const uint8_t *&buffer, uint32_t &total_sz);


    icmp6hdr _header;
    address_type _target_address;
    options_type _options;
    uint32_t _options_size;
    uint32_t reach_time, retrans_timer;
};
}


#endif // TINS_ICMPV6_H
