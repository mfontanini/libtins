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
 
#ifndef TINS_ICMPV6_H
#define TINS_ICMPV6_H

#include <list>
#include <vector>
#include "macros.h"
#include "pdu.h"
#include "ipv6_address.h"
#include "pdu_option.h"
#include "endianness.h"
#include "small_uint.h"
#include "hw_address.h"
#include "small_uint.h"
#include "icmp_extension.h"
#include "cxxstd.h"

namespace Tins {
namespace Memory {

class InputMemoryStream;
class OutputMemoryStream;

} // memory

/**
 * \class ICMPv6
 * \brief Represents an ICMPv6 PDU.
 */
class TINS_API ICMPv6 : public PDU {
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
        ROUTER_RENUMBER = 138,
        NI_QUERY = 139,
        NI_REPLY = 140,
        MLD2_REPORT = 143,
        DHAAD_REQUEST = 144,
        DHAAD_REPLY = 145,
        MOBILE_PREFIX_SOLICIT = 146,
        MOBILE_PREFIX_ADVERT = 147,
        CERT_PATH_SOLICIT = 148,
        CERT_PATH_ADVERT = 149,
        MULTICAST_ROUTER_ADVERT = 151,
        MULTICAST_ROUTER_SOLICIT = 152,
        MULTICAST_ROUTER_TERMINATE = 153,
        RPL_CONTROL_MSG = 155
    };
    
    /**
     * The types of ICMPv6 options.
     */
    enum OptionTypes {
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
        NAACK,
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
    typedef IPv6Address ipaddress_type;
    
    /**
     * The type used to store addresses.
     */
    typedef HWAddress<6> hwaddress_type;
    
    /**
     * The type used to represent ICMPv6 options.
     */
    typedef PDUOption<uint8_t, ICMPv6> option;
    
    /**
     * The type used to store options.
     */
    typedef std::list<option> options_type;
    
    /**
     * \brief The type used to store the new home agent information 
     * option data.
     */
    typedef std::vector<uint16_t> new_ha_info_type;
    
    /**
     * The type used to store the source/target address list options.
     */
    struct addr_list_type {
        typedef std::vector<ipaddress_type> addresses_type;
        
        uint8_t reserved[6];
        addresses_type addresses;
        
        addr_list_type(const addresses_type& addresses = addresses_type())
        : addresses(addresses) {
            std::fill(reserved, reserved + sizeof(reserved), 0);
        }
        
        static addr_list_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the nonce option data.
     */
    typedef std::vector<uint8_t> nonce_type;
    
    /**
     * The type used to store the MTU option.
     */
    typedef std::pair<uint16_t, uint32_t> mtu_type;
    
    /**
     * \brief The type used to store the neighbour advertisement 
     * acknowledgement option data.
     */
    struct naack_type {
        uint8_t code, status;
        uint8_t reserved[4];
        
        naack_type(uint8_t code = 0, uint8_t status = 0)
        : code(code), status(status) {
            std::fill(reserved, reserved + 4, 0);
        }
        
        static naack_type from_option(const option& opt);
    };
    
    /**
     * \brief The type used to store the link layer address option data.
     */
    struct lladdr_type {
        typedef std::vector<uint8_t> address_type;
        
        uint8_t option_code;
        address_type address;
        
        /**
         * Constructor taking an option code and an address.
         * 
         * \param option_code The option code.
         * \param address The address to be stored.
         */
        lladdr_type(uint8_t option_code = 0, 
                    const address_type& address = address_type())
        : option_code(option_code), address(address) {
            
        }
        
        /**
         * \brief Constructor taking an option code and hwaddress_type.
         * 
         * This is a helper constructor, since it'll be common to use
         * hwaddress_type as the link layer address.
         * 
         * \param option_code The option code.
         * \param address The address to be stored.
         */
        lladdr_type(uint8_t option_code, const hwaddress_type& address)
        : option_code(option_code), address(address.begin(), address.end()) {
            
        }
        
        static lladdr_type from_option(const option& opt);
    };
    
    /**
     * Type type used to store the prefix information option data.
     */
    struct prefix_info_type {
        uint8_t prefix_len;
        small_uint<1> A, L;
        uint32_t valid_lifetime,
                 preferred_lifetime,
                 reserved2;
        ipaddress_type prefix;
        
        prefix_info_type(uint8_t prefix_len = 0, 
                         small_uint<1> A = 0,
                         small_uint<1> L = 0,
                         uint32_t valid_lifetime = 0, 
                         uint32_t preferred_lifetime = 0,
                         const ipaddress_type& prefix = ipaddress_type())
        : prefix_len(prefix_len), A(A), L(L), valid_lifetime(valid_lifetime),
          preferred_lifetime(preferred_lifetime), reserved2(0), prefix(prefix) { }
          
        static prefix_info_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the RSA signature option.
     */
    struct rsa_sign_type {
        typedef std::vector<uint8_t> signature_type;
        
        uint8_t key_hash[16];
        signature_type signature;
        
        /**
         * \brief Constructs a rsa_sign_type object.
         * 
         * The first parameter must be a random access iterator
         * which will be used to initialize the key_hash member. 
         * It is assumed that std::distance(hash, end_of_hash) >= 16.
         * 
         * The second and third arguments indicate the start and end of 
         * the sequence which will be used to initialize the signature
         * member.
         * 
         * \param hash A random access iterator used to initialize the
         * key_hash member.
         * \param start A forward iterator pointing to the start of the 
         * sequence which will be used to initialize the signature member.
         * \param end A forward iterator pointing to the end of the 
         * sequence used to initialize signature.
         */
        template <typename RAIterator, typename ForwardIterator>
        rsa_sign_type(RAIterator hash, ForwardIterator start, ForwardIterator end)
        : signature(start, end) {
            std::copy(hash, hash + sizeof(key_hash), key_hash);
        }
        
        /**
         * \brief Constructs a rsa_sign_type object.
         * 
         * The first parameter must be a random access iterator
         * which will be used to initialize the key_hash member. 
         * It is assumed that std::distance(hash, end_of_hash) >= 16.
         * 
         * 
         * \param hash A random access iterator used to initialize the
         * key_hash member.
         * \param sign The signature to be set.
         */
        template <typename RAIterator>
        rsa_sign_type(RAIterator hash, const signature_type& sign)
        : signature(sign) {
            std::copy(hash, hash + sizeof(key_hash), key_hash);
        }
        
        /**
         * \brief Default constructs a rsa_sign_type.
         * 
         * The key_hash member will be 0-initialized.
         */
        rsa_sign_type() {
            std::fill(key_hash, key_hash + sizeof(key_hash), 0);
        }

        static rsa_sign_type from_option(const option& opt);
    };
    
    /**
     * The type used to store IP address/preffix option.
     */
    struct ip_prefix_type {
        uint8_t option_code, prefix_len;
        ipaddress_type address;
        
        ip_prefix_type(uint8_t option_code = 0,
                       uint8_t prefix_len = 0,
                       const ipaddress_type& address = ipaddress_type())
        : option_code(option_code), prefix_len(prefix_len), address(address)
        {}

        static ip_prefix_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the map option.
     */
    struct map_type {
        small_uint<4> dist, pref;
        small_uint<1> r;
        uint32_t valid_lifetime;
        ipaddress_type address;
        
        map_type(small_uint<4> dist = 0,
                 small_uint<4> pref = 0, 
                 small_uint<1> r = 0, 
                 uint32_t valid_lifetime = 0, 
                 const ipaddress_type& address = ipaddress_type())
        : dist(dist), pref(pref), r(r), valid_lifetime(valid_lifetime),
          address(address) { }

        static map_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the route information option.
     */
    struct route_info_type {
        typedef std::vector<uint8_t> prefix_type;
        
        uint8_t prefix_len;
        small_uint<2> pref;
        uint32_t route_lifetime;
        prefix_type prefix;
        
        route_info_type(uint8_t prefix_len = 0, 
                        small_uint<2> pref = 0, 
                        uint32_t route_lifetime = 0,
                        const prefix_type& prefix = prefix_type())
        : prefix_len(prefix_len), pref(pref), route_lifetime(route_lifetime),
          prefix(prefix) { }

        static route_info_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the recursive DNS servers option.
     */
    struct recursive_dns_type {
        typedef std::vector<ipaddress_type> servers_type;
        
        uint32_t lifetime;
        servers_type servers;
        
        recursive_dns_type(uint32_t lifetime = 0, 
                           const servers_type& servers = servers_type())
        : lifetime(lifetime), servers(servers) {}

        static recursive_dns_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the handover key request option.
     */
    struct handover_key_req_type {
        typedef std::vector<uint8_t> key_type;
        
        small_uint<4> AT;
        key_type key;
        
        handover_key_req_type(small_uint<4> AT = 0,
                              const key_type& key = key_type())
        : AT(AT), key(key) { }

        static handover_key_req_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the handover key reply option.
     */
    struct handover_key_reply_type : handover_key_req_type {
        uint16_t lifetime;
        
        handover_key_reply_type(uint16_t lifetime = 0, 
                                small_uint<4> AT = 0,
                                const key_type& key = key_type())
        : handover_key_req_type(AT, key), lifetime(lifetime) { }

        static handover_key_reply_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the handover assist information option.
     */
    struct handover_assist_info_type {
        typedef std::vector<uint8_t> hai_type;
        
        uint8_t option_code;
        hai_type hai;
        
        handover_assist_info_type(uint8_t option_code=0, 
                                  const hai_type& hai = hai_type())
        : option_code(option_code), hai(hai) { }

        static handover_assist_info_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the mobile node identifier option.
     */
    struct mobile_node_id_type {
        typedef std::vector<uint8_t> mn_type;
        
        uint8_t option_code;
        mn_type mn;
        
        mobile_node_id_type(uint8_t option_code=0, 
                            const mn_type& mn = mn_type())
        : option_code(option_code), mn(mn) { }

        static mobile_node_id_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the DNS search list option.
     */
    struct dns_search_list_type {
        typedef std::vector<std::string> domains_type;
        
        uint32_t lifetime;
        domains_type domains;
        
        dns_search_list_type(uint32_t lifetime = 0,
                             const domains_type& domains = domains_type())
        : lifetime(lifetime), domains(domains) { }

        static dns_search_list_type from_option(const option& opt);
    };

    /**
     * The type used to store the timestamp option.
     */
    struct timestamp_type {
        uint8_t reserved[6];
        uint64_t timestamp;

        timestamp_type(uint64_t timestamp = 0)
        : timestamp(timestamp) {
            std::fill(reserved, reserved + sizeof(reserved), 0);
        }

        static timestamp_type from_option(const option& opt);
    };

    /**
     * The type used to store the shortcut limit option.
     */
    struct shortcut_limit_type {
        uint8_t limit, reserved1;
        uint32_t reserved2;

        shortcut_limit_type(uint8_t limit = 0)
        : limit(limit), reserved1(), reserved2() {

        }

        static shortcut_limit_type from_option(const option& opt);
    };

    /**
     * The type used to store new advertisement interval option.
     */
    struct new_advert_interval_type {
        uint16_t reserved;
        uint32_t interval;

        new_advert_interval_type(uint32_t interval = 0)
        : reserved(), interval(interval) {

        }

        static new_advert_interval_type from_option(const option& opt);
    };

    /**
     * The type used to represent a multicast address record
     */
    struct multicast_address_record {
        typedef std::vector<ipaddress_type> sources_type;
        typedef std::vector<uint8_t> aux_data_type;

        multicast_address_record(uint8_t type = 0) : type(type) { }

        multicast_address_record(const uint8_t* buffer, uint32_t total_sz);
        void serialize(uint8_t* buffer, uint32_t total_sz) const;
        uint32_t size() const;

        uint8_t type;
        ipaddress_type multicast_address;
        sources_type sources;
        aux_data_type aux_data;
    };

    /*
     * The type used to store all multicast address records in a packet
     */
    typedef std::list<multicast_address_record> multicast_address_records_list;

    /*
     * The type used to store all source address (from Multicast 
     * Listener Query messages) in a packet 
     */
    typedef std::list<ipaddress_type> sources_list;

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
     * \brief Constructs an ICMPv6 object from a buffer.
     * 
     * If there is not enough size for an ICMPv6 header, a
     * malformed_packet exception is thrown.
     * 
     * Any extra data is stored in a RawPDU.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    ICMPv6(const uint8_t* buffer, uint32_t total_sz);
    
    // Getters

    /**
     *  \brief Getter for the type field.
     *  \return The stored type field value.
     */
    Types type() const {
        return static_cast<Types>(header_.type);
    }

    /**
     *  \brief Getter for the code field.
     *  \return The stored code field value.
     */
    uint8_t code() const {
        return header_.code;
    }

    /**
     *  \brief Getter for the cksum field.
     *  \return The stored cksum field value.
     */
    uint16_t checksum() const {
        return Endian::be_to_host(header_.cksum);
    }

    /**
     *  \brief Getter for the identifier field.
     *  \return The stored identifier field value.
     */
    uint16_t identifier() const {
        return Endian::be_to_host(header_.u_echo.identifier);
    }

    /**
     *  \brief Getter for the sequence field.
     *  \return The stored sequence field value.
     */
    uint16_t sequence() const {
        return Endian::be_to_host(header_.u_echo.sequence);
    }

    /**
     *  \brief Getter for the override field.
     *  \return The stored override field value.
     */
    small_uint<1> override() const {
        return header_.u_nd_advt.override;
    }

    /**
     *  \brief Getter for the solicited field.
     *  \return The stored solicited field value.
     */
    small_uint<1> solicited() const {
        return header_.u_nd_advt.solicited;
    }

    /**
     *  \brief Getter for the router field.
     *  \return The stored router field value.
     */
    small_uint<1> router() const {
        return header_.u_nd_advt.router;
    }

    /**
     *  \brief Getter for the hop limit field.
     *  \return The stored hop limit field value.
     */
    uint8_t hop_limit() const {
        return header_.u_nd_ra.hop_limit;
    }

    /**
     * \brief Getter for the maximum response code field.
     * \return The stored maximum response code field value.
     */
    uint16_t maximum_response_code() const {
        return Endian::be_to_host(header_.u_echo.identifier);
    }

    /**
     *  \brief Getter for the router_pref field.
     *  \return The stored router_pref field value.
     */
    small_uint<2> router_pref() const {
        return header_.u_nd_ra.router_pref;
    }

    /**
     *  \brief Getter for the home_agent field.
     *  \return The stored home_agent field value.
     */
    small_uint<1> home_agent() const {
        return header_.u_nd_ra.home_agent;
    }

    /**
     *  \brief Getter for the other field.
     *  \return The stored other field value.
     */
    small_uint<1> other() const {
        return header_.u_nd_ra.other;
    }

    /**
     *  \brief Getter for the managed field.
     *  \return The stored managed field value.
     */
    small_uint<1> managed() const {
        return header_.u_nd_ra.managed;
    }

    /**
     *  \brief Getter for the router_lifetime field.
     *  \return The stored router_lifetime field value.
     */
    uint16_t router_lifetime() const {
        return Endian::be_to_host(header_.u_nd_ra.router_lifetime);
    }
    
    /**
     *  \brief Getter for the reachable_time field.
     *  \return The stored reachable_time field value.
     */
    uint32_t reachable_time() const {
        return Endian::be_to_host(reach_time_);
    }
    
    /**
     *  \brief Getter for the retransmit_timer field.
     *  \return The stored retransmit_timer field value.
     */
    uint32_t retransmit_timer() const {
        return Endian::be_to_host(retrans_timer_);
    }
    
    /**
     *  \brief Getter for the target address field.
     *  \return The stored target address field value.
     */
    const ipaddress_type& target_addr() const {
        return target_address_;
    }
    
    /**
     *  \brief Getter for the destination address field.
     *  \return The stored destination address field value.
     */
    const ipaddress_type& dest_addr() const {
        return dest_address_;
    }

    /**
     * \brief Getter for the multicast address field.
     *
     * Note that this field is only valid for Multicast Listener Query
     * Message packets
     * \return The stored multicast address field value.
     */
    const ipaddress_type& multicast_addr() const {
        return multicast_address_;
    }

    /**
     *  \brief Getter for the ICMPv6 options.
     *  \return The stored options.
     */
    const options_type& options() const {
        return options_;
    }

    /**
     * \brief Getter for the length field.
     *
     * \return Returns the length field value.
     */
    uint8_t length() const { 
        return header_.rfc4884.length;
    }

    /**
     * \brief Getter for the multicast address records field
     */
    const multicast_address_records_list& multicast_address_records() const {
        return multicast_records_;
    }

    /**
     * \brief Getter for the multicast address records field.
     *
     * Note that this field is only valid for Multicast Listener Query Message
     * packets
     */
    const sources_list& sources() const {
        return sources_;
    }

    /**
     * \brief Getter for the Suppress Router-Side Processing field.
     *
     * Note that this field is only valid for Multicast Listener Query Message
     * packets
     */
    small_uint<1> supress() const {
        return mlqm_.supress;
    }

    /**
     * \brief Getter for the Querier's Robustnes Variable field.
     *
     * Note that this field is only valid for Multicast Listener Query Message
     * packets
     */
    small_uint<3> qrv() const {
        return mlqm_.qrv;
    }

    /**
     * \brief Getter for the Querier's Query Interval Code field.
     *
     * Note that this field is only valid for Multicast Listener Query Message
     * packets
     */
    uint8_t qqic() const {
        return mlqm_.qqic;
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
     *  \brief Setter for the maximum response code field.
     *  \param new_hop_limit The new maximum response code field value.
     */
    void maximum_response_code(uint16_t maximum_response_code);

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
    void target_addr(const ipaddress_type& new_target_addr);
    
    /**
     *  \brief Setter for the destination address field.
     *  \param new_dest_addr The new destination address field value.
     */
    void dest_addr(const ipaddress_type& new_dest_addr);

    /**
     * \brief Setter for the multicast address field.
     *
     * Note that this field is only valid if the type is MGM_QUERY
     *
     * \param new_multicast_addr The new multicast address field value.
     */
    void multicast_addr(const ipaddress_type& new_multicast_addr);

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
     *  \brief Setter for the multicast address records field.
     *
     * This field is only valid if the type of this PDU is MLD2_REPORT
     */
    void multicast_address_records(const multicast_address_records_list& records);

    /**
     * \brief Setter for the sources field.
     *
     * This field is only valid if the type of this PDU is MGM_QUERY
     */
    void sources(const sources_list& new_sources);

    /**
     * \brief Setter for the supress field.
     *
     * This field is only valid if the type of this PDU is MGM_QUERY
     */
    void supress(small_uint<1> value);

    /**
     * \brief Setter for the Querier's Robustness Variable field.
     *
     * This field is only valid if the type of this PDU is MGM_QUERY
     */
    void qrv(small_uint<3> value);

    /**
     * \brief Setter for the Querier's Query Interval Code field.
     *
     * This field is only valid if the type of this PDU is MGM_QUERY
     */
    void qqic(uint8_t value);

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
     * \brief Checks whether this ICMPv6 object has a target_addr field.
     * 
     * This depends on the type field.
     */
    bool has_dest_addr() const {
        return type() == REDIRECT;
    }
    
    /**
     * \brief Adds an ICMPv6 option.
     * 
     * The option is added after the last option in the option 
     * fields.
     * 
     * \param option The option to be added
     */
    void add_option(const option& option);
    
    #if TINS_IS_CXX11
        /**
         * \brief Adds an ICMPv6 option.
         * 
         * The option is move-constructed.
         * 
         * \param option The option to be added.
         */
        void add_option(option &&option) {
            internal_add_option(option);
            options_.push_back(std::move(option));
        }
    #endif

    /**
     * \brief Removes an ICMPv6 option.
     * 
     * If there are multiple options of the given type, only the first one
     * will be removed.
     *
     * \param type The type of the option to be removed.
     * \return true if the option was removed, false otherwise.
     */
    bool remove_option(OptionTypes type);

    /**
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. This size includes the
     * payload and options size. \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Returns the trailer size.
     *
     * This method overrides PDU::trailer_size. This size will hold the extensions size
     *
     * \sa PDU::header_size
     */
    uint32_t trailer_size() const;
    
    /** 
     * \brief Getter for the extensions field.
     *
     * \return The extensions field
     */
    const ICMPExtensionsStructure& extensions() const {
        return extensions_;
    }

    /** 
     * \brief Getter for the extensions field.
     *
     * \return The extensions field
     */
    ICMPExtensionsStructure& extensions() {
        return extensions_;
    }

    /**
     * \brief Indicates whether this object contains ICMP extensions
     */
    bool has_extensions() const {
        return !extensions_.extensions().empty();
    }

    /**
     * \brief Sets whether the length field will be set for packets that use it
     *
     * As defined in RFC 4884, some ICMP packet types can have a length field. This
     * method controlers whether the length field is set or not.
     *
     * Note that this only indicates that the packet should use this field. The 
     * actual value will be set during the packet's serialization.
     *
     * Note that, in order to br RFC compliant, if the size of the encapsulated
     * PDU is greater than 128, the length field will always be set, regardless
     * of whether this method was called or not.
     *
     * /param value true iff the length field should be set appropriately
     */
    void use_length_field(bool value);

    /** 
     * \brief Check whether ptr points to a valid response for this PDU.
     *
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const;

    /**
     * \brief Searchs for an option that matchs the given flag.
     * 
     * If the header is not found, a null pointer is returned. 
     * Deleting the returned pointer will result in <b>undefined 
     * behaviour</b>.
     * 
     * \param type The option identifier to be searched.
     */
    const option* search_option(OptionTypes type) const;

    /**
     * \sa PDU::clone
     */
    ICMPv6* clone() const {
        return new ICMPv6(*this);
    }

    /** 
     * \brief Indicates whether to use MLDv2
     *
     * If this is set to true, then MLDv2 will be used rather than MLDv1 when
     * serializing Multicast Listener Discovery messages. By default,
     * MLDv2 will be used.
     *
     * \param value The value to set
     */
    void use_mldv2(bool value);
    
    // ****************************************************************
    //                          Option setters
    // ****************************************************************
    
    /**
     * \brief Setter for the source link layer address option.
     * 
     * \param addr The source link layer address.
     */
    void source_link_layer_addr(const hwaddress_type& addr);
    
    /**
     * \brief Setter for the target link layer address option.
     * 
     * \param addr The target link layer address.
     */
    void target_link_layer_addr(const hwaddress_type& addr);
    
    /**
     * \brief Setter for the prefix information option.
     * 
     * \param info The prefix information.
     */
    void prefix_info(prefix_info_type info);
    
    /**
     * \brief Setter for the redirect header option.
     * 
     * \param data The redirect header option data.
     */
    void redirect_header(const byte_array& data);
    
    /**
     * \brief Setter for the MTU option.
     * 
     * \param value The MTU option data.
     */
    void mtu(const mtu_type& value);
    
    /**
     * \brief Setter for the shortcut limit option.
     * 
     * \param value The shortcut limit option data.
     */
    void shortcut_limit(const shortcut_limit_type& value);
    
    /**
     * \brief Setter for the new advertisement interval option.
     * 
     * \param value The new advertisement interval option data.
     */
    void new_advert_interval(const new_advert_interval_type& value);
    
    /**
     * \brief Setter for the new home agent information option.
     * 
     * \param value The new home agent information option data.
     */
    void new_home_agent_info(const new_ha_info_type& value);
    
    /**
     * \brief Setter for the new source address list option.
     * 
     * \param value The new source address list option data.
     */
    void source_addr_list(const addr_list_type& value);
    
    /**
     * \brief Setter for the new target address list option.
     * 
     * \param value The new target address list option data.
     */
    void target_addr_list(const addr_list_type& value);
    
    /**
     * \brief Setter for the new RSA signature option.
     * 
     * \param value The new RSA signature option data.
     */
    void rsa_signature(const rsa_sign_type& value);
    
    /**
     * \brief Setter for the new timestamp option.
     * 
     * \param value The new timestamp option data.
     */
    void timestamp(const timestamp_type& value);
    
    /**
     * \brief Setter for the new nonce option.
     * 
     * \param value The new nonce option data.
     */
    void nonce(const nonce_type& value);
    
    /**
     * \brief Setter for the new IP address/prefix option.
     * 
     * \param value The new IP address/prefix option data.
     */
    void ip_prefix(const ip_prefix_type& value);

    /**
     * \brief Setter for the new link layer address option.
     * 
     * \param value The new link layer address option data.
     */
    void link_layer_addr(lladdr_type value);

    /**
     * \brief Setter for the neighbour advertisement acknowledgement option.
     * 
     * \param value The new naack option data.
     */
    void naack(const naack_type& value);
    
    /**
     * \brief Setter for the map option.
     * 
     * \param value The new map option data.
     */
    void map(const map_type& value);
    
    /**
     * \brief Setter for the route information option.
     * 
     * \param value The new route information option data.
     */
    void route_info(const route_info_type& value);
    
    /**
     * \brief Setter for the recursive DNS servers option.
     * 
     * \param value The new recursive DNS servers option data.
     */
    void recursive_dns_servers(const recursive_dns_type& value);
    
    /**
     * \brief Setter for the handover key request option.
     * 
     * \param value The new handover key request option data.
     */
    void handover_key_request(const handover_key_req_type& value);
    
    /**
     * \brief Setter for the handover key reply option.
     * 
     * \param value The new handover key reply option data.
     */
    void handover_key_reply(const handover_key_reply_type& value);
    
    /**
     * \brief Setter for the handover assist info option.
     * 
     * \param value The new handover assist info option data.
     */
    void handover_assist_info(const handover_assist_info_type& value);
    
    /**
     * \brief Setter for the mobile node identifier option.
     * 
     * \param value The new mobile node identifier option data.
     */
    void mobile_node_identifier(const mobile_node_id_type& value);
    
    /**
     * \brief Setter for the DNS search list option.
     * 
     * \param value The new DNS search list option data.
     */
    void dns_search_list(const dns_search_list_type& value);
    
    // ****************************************************************
    //                          Option getters
    // ****************************************************************
    
    /**
     * \brief Getter for the source link layer address option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    hwaddress_type source_link_layer_addr() const;
    
    /**
     * \brief Getter for the target link layer address option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    hwaddress_type target_link_layer_addr() const;
        
    /**
     * \brief Getter for the prefix information option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    prefix_info_type prefix_info() const;
    
    /**
     * \brief Getter for the redirect header option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    byte_array redirect_header() const;
    
    /**
     * \brief Getter for the MTU option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    mtu_type mtu() const;
    
    /**
     * \brief Getter for the shortcut limit option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    shortcut_limit_type shortcut_limit() const;
    
    /**
     * \brief Getter for the new advertisement interval option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    new_advert_interval_type new_advert_interval() const;
    
    /**
     * \brief Getter for the new home agent information option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    new_ha_info_type new_home_agent_info() const;
    
    /**
     * \brief Getter for the source address list option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    addr_list_type source_addr_list() const;
    
    /**
     * \brief Getter for the target address list option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    addr_list_type target_addr_list() const;
    
    /**
     * \brief Getter for the RSA signature option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    rsa_sign_type rsa_signature() const;
    
    /**
     * \brief Getter for the timestamp option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    timestamp_type timestamp() const;
    
    /**
     * \brief Getter for the nonce option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    nonce_type nonce() const;
    
    /**
     * \brief Getter for the IP address/prefix option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    ip_prefix_type ip_prefix() const;
    
    /**
     * \brief Getter for the link layer address option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    lladdr_type link_layer_addr() const;
    
    /**
     * \brief Getter for the neighbour advertisement acknowledgement
     * option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    naack_type naack() const;
    
    /**
     * \brief Getter for the map option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    map_type map() const;
    
    /**
     * \brief Getter for the route information option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    route_info_type route_info() const;
    
    /**
     * \brief Getter for the recursive dns servers option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    recursive_dns_type recursive_dns_servers() const;
    
    /**
     * \brief Getter for the handover key request option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    handover_key_req_type handover_key_request() const;
    
    /**
     * \brief Getter for the handover key reply option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    handover_key_reply_type handover_key_reply() const;
    
    /**
     * \brief Getter for the handover key reply option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    handover_assist_info_type handover_assist_info() const;
    
    /**
     * \brief Getter for the mobile node identifier option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    mobile_node_id_type mobile_node_identifier() const;
    
    /**
     * \brief Getter for the mobile node identifier option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    dns_search_list_type dns_search_list() const;
private:
    TINS_BEGIN_PACK
    struct icmp6_header {
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
            struct {
                uint8_t length;
                uint8_t unused[3];
            } rfc4884;
            // Multicast Listener Report Message (mld2)
            struct {
                uint16_t reserved;
                uint16_t record_count;
            } mlrm2;
        };
    } TINS_END_PACK;

    TINS_BEGIN_PACK
    struct multicast_listener_query_message_fields {
        uint8_t reserved:4,
                supress:1,
                qrv:3;
        uint8_t qqic;
    } TINS_END_PACK;
    
    void internal_add_option(const option& option);
    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent);
    bool has_options() const;
    void write_option(const option& opt, Memory::OutputMemoryStream& stream);
    void parse_options(Memory::InputMemoryStream& stream);
    void add_addr_list(uint8_t type, const addr_list_type& value);
    addr_list_type search_addr_list(OptionTypes type) const;
    options_type::const_iterator search_option_iterator(OptionTypes type) const;
    options_type::iterator search_option_iterator(OptionTypes type);
    void try_parse_extensions(Memory::InputMemoryStream& stream);
    bool are_extensions_allowed() const;
    uint32_t get_adjusted_inner_pdu_size() const;
    uint8_t get_option_padding(uint32_t data_size);

    template <template <typename> class Functor>
    const option* safe_search_option(OptionTypes opt, uint32_t size) const {
        const option* option = search_option(opt);
        if (!option || Functor<uint32_t>()(option->data_size(), size)) {
            throw option_not_found();
        }
        return option;
    }

    template <typename T>
    T search_and_convert(OptionTypes type) const {
        const option* opt = search_option(type);
        if (!opt) {
            throw option_not_found();
        }
        return opt->to<T>();
    }

    icmp6_header header_;
    ipaddress_type target_address_;
    ipaddress_type dest_address_;
    ipaddress_type multicast_address_;
    options_type options_;
    uint32_t options_size_;
    uint32_t reach_time_, retrans_timer_;
    multicast_address_records_list multicast_records_;
    multicast_listener_query_message_fields mlqm_;
    sources_list sources_;
    ICMPExtensionsStructure extensions_;
    bool use_mldv2_;
};

} // Tins

#endif // TINS_ICMPV6_H
