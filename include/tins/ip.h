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

#ifndef TINS_IP_H
#define TINS_IP_H

#include <list>
#include "pdu.h"
#include "small_uint.h"
#include "endianness.h"
#include "ip_address.h"
#include "pdu_option.h"
#include "macros.h"
#include "cxxstd.h"

namespace Tins {

    /**
     * \class IP
     * \brief Class that represents an IP PDU.
     * 
     * By default, IP PDUs are initialized, setting TTL to IP::DEFAULT_TTL,
     * id field to 1 and version to 4. Taking this into account, users
     * should set destination and source port and would be enough to send one.
     */
    class IP : public PDU {
    public:
        /**
         * This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::IP;
    
        /**
         * The type used to store addresses.
         */
        typedef IPv4Address address_type;

        /**
         * \brief Enum indicating the option's class.
         *
         * Enum OptionClass represents the different classes of
         * IP Options.
         */
        enum OptionClass {
            CONTROL = 0,
            MEASUREMENT = 2
        };

        /**
         * \brief Enum indicating the option's id number.
         *
         * Enum Option indicates the possible IP Options.
         */
        enum OptionNumber {
            END = 0,
            NOOP = 1,
            SEC = 2,
            LSSR = 3,
            TIMESTAMP = 4,
            EXTSEC = 5,
            RR = 7,
            SID = 8,
            SSRR = 9,
            MTUPROBE = 11,
            MTUREPLY = 12,
            EIP = 17,
            TR = 18,
            ADDEXT = 19,
            RTRALT = 20,
            SDB = 21,
            DPS = 23,
            UMP = 24,
            QS = 25
        };
        
        /**
         * \brief The type used to represent an option's type.
         */
        TINS_BEGIN_PACK
        struct option_identifier {
        #if TINS_IS_LITTLE_ENDIAN
            uint8_t number:5,
                    op_class:2,
                    copied:1;
        #elif TINS_IS_BIG_ENDIAN
            uint8_t copied:1,
                    op_class:2,
                    number:5;
        #endif
            /**
             * \brief Default constructor.
             * 
             * Initializes every field to 0.
             */
            option_identifier() 
            #if TINS_IS_LITTLE_ENDIAN
            : number(0), op_class(0), copied(0) {}
            #else
            : copied(0), op_class(0), number(0) {}
            #endif
            
            /**
             * \brief Constructs this option from a single uint8_t value.
             * 
             * This parses the value and initializes each field with the
             * appropriate value.
             * 
             * \param value The value to be parsed and used for 
             * initialization
             */
            option_identifier(uint8_t value) 
            #if TINS_IS_LITTLE_ENDIAN
            : number(value & 0x1f), 
              op_class((value >> 5) & 0x03), 
              copied((value >> 7) & 0x01) {}
            #elif TINS_IS_BIG_ENDIAN
            : copied((value >> 7) & 0x01),
              op_class((value >> 5) & 0x03), 
              number(value & 0x1f) {}
            #endif
            
            /**
             * Constructor using user provided values for each field.
             * \param number The number field value.
             * \param op_class The option class field value.
             * \param copied The copied field value.
             */
            option_identifier(OptionNumber number, OptionClass op_class,
              small_uint<1> copied) 
            #if TINS_IS_LITTLE_ENDIAN
            : number(number), op_class(op_class), copied(copied) {}
            #else
            : copied(copied), op_class(op_class), number(number) {}
            #endif
            
            /**
             * \brief Equality operator.
             */
            bool operator==(const option_identifier &rhs) const {
                return number == rhs.number && op_class == rhs.op_class && copied == rhs.copied;
            }
        } TINS_END_PACK;
        
        /**
         * The IP options type.
         */
        typedef PDUOption<option_identifier, IP> option;

        /**
         * The type of the security option.
         */
        struct security_type {
            uint16_t security, compartments;
            uint16_t handling_restrictions;
            small_uint<24> transmission_control;
            
            security_type(uint16_t sec = 0, uint16_t comp = 0,
              uint16_t hand_res = 0, small_uint<24> tcc = 0)
            : security(sec), compartments(comp), 
              handling_restrictions(hand_res), transmission_control(tcc) 
              {}
            
            static security_type from_option(const option &opt);
        };
        
        /**
         * The type of the Loose Source and Record Route
         */
        struct generic_route_option_type {
            typedef std::vector<address_type> routes_type;
            
            uint8_t pointer;
            routes_type routes;
            
            generic_route_option_type(uint8_t ptr = 0, 
              routes_type rts = routes_type())
            : pointer(ptr), routes(rts) {}
            
            static generic_route_option_type from_option(const option &opt);
        };
        
        /**
         * The type of the Loose Source and Record Route
         */
        typedef generic_route_option_type lsrr_type;
        
        /**
         * The type of the Strict Source and Record Route
         */
        typedef generic_route_option_type ssrr_type;
        
        /**
         * The type of the Record Route
         */
        typedef generic_route_option_type record_route_type;

        /**
         * The type used to store IP options.
         */
        typedef std::list<option> options_type;

        /**
         * \brief Constructor for building the IP PDU.
         *
         * Both the destination and source IP address can be supplied.
         * By default, those fields are initialized using the IP 
         * address 0.0.0.0.
         *
         * \param ip_dst The destination ip address(optional).
         * \param ip_src The source ip address(optional).
         */
        IP(address_type ip_dst = address_type(), 
            address_type ip_src = address_type());

        /**
         * \brief Constructs an IP object from a buffer and adds all 
         * identifiable PDUs found in the buffer as children of this 
         * one.
         * 
         * If there is not enough size for an IP header, a 
         * malformed_packet exception is thrown.
         * 
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        IP(const uint8_t *buffer, uint32_t total_sz);

        /* Getters */

        /**
         * \brief Getter for the header length field.
         *
         * \return The number of dwords the header occupies in an uin8_t.
         */
        small_uint<4> head_len() const { return this->_ip.ihl; }

        /**
         * \brief Getter for the type of service field.
         *
         * \return The this IP PDU's type of service.
         */
        uint8_t tos() const { return _ip.tos; }

        /**
         * \brief Getter for the total length field.
         *
         * \return The total length of this IP PDU.
         */
        uint16_t tot_len() const { 
            return Endian::be_to_host(_ip.tot_len); 
        }

        /**
         * \brief Getter for the id field.
         *
         * \return The id for this IP PDU.
         */
        uint16_t id() const { return Endian::be_to_host(_ip.id); }

        /**
         * \brief Getter for the fragment offset field.
         *
         * \return The fragment offset for this IP PDU.
         */
        uint16_t frag_off() const { return Endian::be_to_host(_ip.frag_off); }

        /**
         * \brief Getter for the time to live field.
         *
         * \return The time to live for this IP PDU.
         */
        uint8_t ttl() const { return _ip.ttl; }

        /**
         * \brief Getter for the protocol field.
         *
         * \return The protocol for this IP PDU.
         */
        uint8_t protocol() const { return _ip.protocol; }

        /**
         * \brief Getter for the checksum field.
         *
         * \return The checksum for this IP PDU.
         */
        uint16_t checksum() const { return Endian::be_to_host(_ip.check); }

        /**
         * \brief Getter for the source address field.
         *
         * \return The source address for this IP PDU.
         */
        address_type src_addr() const { return address_type(_ip.saddr); }

        /** 
         * \brief Getter for the destination address field.
         * \return The destination address for this IP PDU.
         */
        address_type dst_addr() const  { return address_type(_ip.daddr); }
        
        /** 
         * \brief Getter for the version field.
         * \return The version for this IP PDU.
         */
        small_uint<4> version() const  { return _ip.version; }

        /** 
         * \brief Getter for the IP options.
         * \return The stored options.
         */
        const options_type &options() const  { return _ip_options; }

        /* Setters */

        /**
         * \brief Setter for the type of service field.
         *
         * \param new_tos The new type of service.
         */
        void tos(uint8_t new_tos);

        /**
         * \brief Setter for the id field.
         *
         * \param new_id The new id.
         */
        void id(uint16_t new_id);

        /**
         * \brief Setter for the fragment offset field.
         *
         * \param new_frag_off The new fragment offset.
         */
        void frag_off(uint16_t new_frag_off);

        /**
         * \brief Setter for the time to live field.
         *
         * \param new_ttl The new time to live.
         */
        void ttl(uint8_t new_ttl);

        /**
         * \brief Setter for the protocol field.
         *
         * Note that this protocol will be overwritten using the 
         * inner_pdu's protocol type during serialization unless the IP 
         * datagram is fragmented. 
         * 
         * If the packet is fragmented and was originally sniffed, the
         * original protocol type will be kept when serialized.
         * 
         * If this packet has been crafted manually and the inner_pdu
         * is, for example, a RawPDU, then setting the protocol yourself
         * is necessary.
         * 
         * \param new_protocol The new protocol.
         */
        void protocol(uint8_t new_protocol);

        /**
         * \brief Setter for the source address field.
         *
         * \param ip The source address to be set.
         */
        void src_addr(address_type ip);

        /**
         * \brief Setter for the destination address field.
         *
         * \param ip The destination address to be set.
         */
        void dst_addr(address_type ip);
        
        /**
         * \brief Setter for the version field.
         *
         * \param ver The version field to be set.
         */
        void version(small_uint<4> ver);

        /**
         * \brief Adds an IP option.
         * 
         * The option is added after the last option in the option 
         * fields.
         * 
         * \param opt The option to be added
         */
        void add_option(const option &opt);
        
        #if TINS_IS_CXX11
            /**
             * \brief Adds an IP option.
             * 
             * The option is move-constructed.
             * 
             * \param opt The option to be added.
             */
            void add_option(option &&opt) {
                internal_add_option(opt);
                _ip_options.push_back(std::move(opt));
            }

            /**
             * \brief Adds an IP option.
             * 
             * The option is constructed from the provided parameters.
             * 
             * \param args The arguments to be used in the option's 
             * constructor.
             */
            template<typename... Args>
            void add_option(Args&&... args) {
                _ip_options.emplace_back(std::forward<Args>(args)...);
                internal_add_option(_ip_options.back());
            }
        #endif

        /**
         * \brief Searchs for an option that matchs the given flag.
         * 
         * If the option is not found, a null pointer is returned. 
         * Deleting the returned pointer will result in <b>undefined 
         * behaviour</b>.
         * 
         * \param id The option identifier to be searched.
         */
        const option *search_option(option_identifier id) const;

        // Option setters
        
        /**
         * \brief Adds an End Of List option.
         */
        void eol();

        /**
         * \brief Adds a NOP option.
         */
        void noop();

        /**
         * \brief Adds a security option.
         *
         * \param data The data to be stored in this option.
         */
        void security(const security_type &data);
        
        /**
         * \brief Adds a Loose Source and Record Route option.
         *
         * \param data The data to be stored in this option.
         */
        void lsrr(const lsrr_type &data) {
            add_route_option(131, data);
        }
        
        /**
         * \brief Adds a Strict Source and Record Route option.
         *
         * \param data The data to be stored in this option.
         */
        void ssrr(const ssrr_type &data) {
            add_route_option(137, data);
        }
        
        /**
         * \brief Adds a Record Route option.
         *
         * \param data The data to be stored in this option.
         */
        void record_route(const record_route_type &data) {
            add_route_option(7, data);
        }
        
        /**
         * \brief Adds a Stream Identifier option.
         *
         * \param stream_id The stream id to be stored in this option.
         */
        void stream_identifier(uint16_t stream_id);
        
        // Option getters
        
        /**
         * \brief Searchs and returns a security option.
         * 
         * If no such option exists, an option_not_found exception
         * is thrown.
         * 
         * \return security_type containing the option found.
         */
        security_type security() const;
        
        /**
         * \brief Searchs and returns a Loose Source and Record Route 
         * option.
         * 
         * If no such option exists, an option_not_found exception
         * is thrown.
         * 
         * \return lsrr_type containing the option found.
         */
        lsrr_type lsrr() const {
            return search_route_option(131);
        }
        
        /**
         * \brief Searchs and returns a Strict Source and Record Route 
         * option.
         * 
         * If no such option exists, an option_not_found exception
         * is thrown.
         * 
         * \return ssrr_type containing the option found.
         */
        ssrr_type ssrr() const {
            return search_route_option(137);
        }
        
        /**
         * \brief Searchs and returns a Record Route option.
         * 
         * If no such option exists, an option_not_found exception
         * is thrown.
         * 
         * \return record_route_type containing the option found.
         */
        record_route_type record_route() const {
            return search_route_option(7);
        }

        /**
         * \brief Searchs and returns a Stream Identifier option.
         * 
         * If no such option exists, an option_not_found exception
         * is thrown.
         * 
         * \return uint16_t containing the option found.
         */
        uint16_t stream_identifier() const;

        /* Virtual methods */

        /**
         * \brief Returns the header size.
         *
         * This metod overrides PDU::header_size. \sa PDU::header_size
         */
        uint32_t header_size() const;

        /**
         * \sa PDU::send()
         */
        void send(PacketSender &sender, const NetworkInterface &);

        /**
         * \brief Check wether ptr points to a valid response for this PDU.
         *
         * \sa PDU::matches_response
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        bool matches_response(const uint8_t *ptr, uint32_t total_sz) const;

        /**
         * \brief Receives a matching response for this packet.
         *
         * \sa PDU::recv_response
         * \param sender The packet sender which will receive the packet.
         */
        PDU *recv_response(PacketSender &sender, const NetworkInterface &);

        /**
         * Indicates whether this PDU is fragmented.
         *
         * \return true if this PDU is fragmented, false otherwise.
         */
        bool is_fragmented() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::IP; }

        /**
         * \sa PDU::clone
         */
        IP *clone() const {
            return new IP(*this);
        }
    private:
        static const uint8_t DEFAULT_TTL;

        TINS_BEGIN_PACK
        struct iphdr {
        #if TINS_IS_LITTLE_ENDIAN
            uint8_t ihl:4,
                    version:4;
        #else
            uint8_t version:4,
                    ihl:4;
        #endif
            uint8_t tos;
            uint16_t tot_len;
            uint16_t id;
            uint16_t frag_off;
            uint8_t ttl;
            uint8_t protocol;
            uint16_t check;
            uint32_t saddr;
            uint32_t daddr;
            /*The options start here. */
        } TINS_END_PACK;


        void head_len(small_uint<4> new_head_len);
        void tot_len(uint16_t new_tot_len);

        void prepare_for_serialize(const PDU *parent);
        void internal_add_option(const option &option);
        void init_ip_fields();
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        uint8_t* write_option(const option &opt, uint8_t* buffer);
        void add_route_option(option_identifier id, const generic_route_option_type &data);
        generic_route_option_type search_route_option(option_identifier id) const;
        void checksum(uint16_t new_check);

        iphdr _ip;
        uint16_t _options_size, _padded_options_size;
        options_type _ip_options;
    };
}

#endif // TINS_IP_H
