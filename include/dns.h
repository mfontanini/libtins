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

#ifndef TINS_DNS_H
#define TINS_DNS_H

#include <stdint.h>
#include <list>
#include <vector>
#include <cstring>
#include <string>
#include <map>
#include "macros.h"
#include "pdu.h"
#include "endianness.h"

namespace Tins {
    class IPv4Address;
    class IPv6Address;
    
    /**
     * \class DNS
     * \brief Represents a DNS PDU.
     *
     * This class represents the DNS PDU, and allows easy access
     * to queries and answer records. 
     *
     * The DNS PDU is not parsed automatically while sniffing, so you will
     * have to parse it manually from an UDP packet's payload, for example:
     *
     * \code
     * // Assume we get an udp packet from somewhere.
     * UDP udp = get_udp_packet();
     *
     * // Now:
     * // 1 - Get the RawPDU layer (contains the payload).
     * // 2 - Construct a DNS object over its contents.
     * DNS dns = udp.rfind_pdu<RawPDU>().to<DNS>();
     *
     * // Now use the DNS object!
     * for(const auto& query : dns.queries()) {
     *     // Process a query
     * }
     * \endcode
     */
    class DNS : public PDU {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DNS;
        
        /**
         * The DNS type.
         */
        enum QRType {
            QUERY = 0,
            RESPONSE = 1
        };
        
        /**
         * \brief Query types enum.
         */
        enum QueryType {
            A = 1,
            NS,
            MD,
            MF,
            CNAME,
            SOA,
            MB,
            MG,
            MR,
            NULL_R,
            WKS,
            PTR,
            HINFO,
            MINFO,
            MX,
            TXT,
            RP,
            AFSDB,
            X25,
            ISDN,
            RT,
            NSAP,
            NSAP_PTR,
            SIG,
            KEY,
            PX,
            GPOS,
            AAAA,
            LOC,
            NXT,
            EID,
            NIMLOC,
            SRV,
            ATMA,
            NAPTR,
            KX,
            CERT,
            A6,
            DNAM,
            SINK,
            OPT,
            APL,
            DS,
            SSHFP,
            IPSECKEY,
            RRSIG,
            NSEC,
            DNSKEY,
            DHCID,
            NSEC3,
            NSEC3PARAM
        };
        
        enum QueryClass {
            IN = 1,
            CH = 3,
            HS = 4,
            ANY = 255
        };
        
        /**
         * \brief Struct that represent DNS queries.
         */
        class Query {
        public:
            /**
             * \brief Constructs a DNS query.
             * 
             * \param nm The name of the domain being resolved.
             * \param tp The query type.
             * \param cl The query class.
             */
            Query(const std::string &nm, QueryType tp, QueryClass cl) 
            : name_(nm), type_(tp), qclass_(cl) {}
            
            /**
             * \brief Default constructs this Query.
             */
            Query() : type_(), qclass_() {}
            
            /**
             * \brief Setter for the name field.
             * 
             * \param nm The name to be set.
             */
            void dname(const std::string &nm) {
                name_ = nm;
            }
            
            /**
             * \brief Setter for the query type field.
             * 
             * \param tp The query type to be set.
             */
            void type(QueryType tp) {
                type_ = tp;
            }
            
            /**
             * \brief Setter for the query class field.
             * 
             * \param cl The query class to be set.
             */
            void query_class(QueryClass cl) {
                qclass_ = cl;
            }
            
            /**
             * \brief Getter for the name field.
             */
            const std::string &dname() const { return name_; }
            
            /**
             * \brief Getter for the query type field.
             */
            QueryType type() const { return type_; }
            
            /**
             * \brief Getter for the query class field.
             */
            QueryClass query_class() const { return qclass_; }
        private:
            std::string name_;
            QueryType type_;
            QueryClass qclass_;
        };
        
        /**
         * \brief Struct that represent DNS resource records.
         */
        class Resource {
        public:
            /**
             * Constructs a Resource object.
             *
             * \param dname The domain name for which this records 
             * provides an answer.
             * \param data The resource's payload.
             * \param type The type of this record.
             * \param rclass The class of this record.
             * \param ttl The time-to-live of this record.
             */
            Resource(const std::string &dname, const std::string &data, 
              uint16_t type, uint16_t rclass, uint32_t ttl) 
            : dname_(dname), data_(data), type_(type), qclass_(rclass), ttl_(ttl) {}
            
            Resource() : type_(), qclass_(), ttl_() {}
            
            /**
             * \brief Getter for the domain name field.
             * 
             * This returns the domain name for which this record 
             * provides an answer.
             */
            const std::string &dname() const { return dname_; }
            
            /**
             * Getter for the data field. 
             */
            const std::string &data() const { return data_; }
            
            /**
             * Getter for the query type field.
             */
            uint16_t type() const { return type_; }
            
            /**
             * Getter for the query class field.
             */
            uint16_t query_class() const { return qclass_; }
            
            /**
             * Getter for the type field.
             */
            uint32_t ttl() const { return ttl_; }

            /**
             * Setter for the domain name field.
             */
            void dname(const std::string &data) {
                dname_ = data;
            }

            /**
             * \brief Setter for the data field.
             *
             * The data will be encoded properly by the DNS class before
             * being added to this packet. That means that if the type is
             * A or AAAA, it will be properly encoded as an IPv4 or
             * IPv6 address. 
             * 
             * The same happens for records that contain domain names,
             * such as NS or CNAME. This data will be encoded using 
             * DNS domain name encoding.
             */
            void data(const std::string &data) {
                data_ = data;
            }

            /**
             * Setter for the type field.
             */
            void type(uint16_t data) {
                type_ = data;
            }

            /**
             * Setter for the class field.
             */
            void query_class(uint16_t data) {
                qclass_ = data;
            }

            /**
             * Setter for the time-to-live field.
             */
            void ttl(uint16_t data) {
                ttl_ = data;
            }
        private:
            std::string dname_, data_;
            uint16_t type_, qclass_;
            uint32_t ttl_;
        };
        
        typedef std::list<Query> queries_type;
        typedef std::list<Resource> resources_type;
        typedef IPv4Address address_type;
        typedef IPv6Address address_v6_type;
        
        /**
         * \brief Default constructor.
         * 
         * This constructor initializes every field to 0.
         */
        DNS();
        
        /**
         * \brief Constructs a DNS object from a buffer.
         * 
         * If there's not enough size for the DNS header, or any of the
         * records are malformed, a malformed_packet is be thrown.
         * 
         * \param buffer The buffer from which this PDU will be 
         * constructed.
         * \param total_sz The total size of the buffer.
         */
        DNS(const uint8_t *buffer, uint32_t total_sz);
        
        // Getters
        
        /**
         * \brief Setter for the id field.
         * 
         * \return uint16_t containing the value of the id field.
         */
        uint16_t id() const { return Endian::be_to_host(dns.id); }
        
        /**
         * \brief Setter for the query response field.
         * 
         * \return QRType containing the value of the query response
         * field.
         */
        QRType type() const { return static_cast<QRType>(dns.qr); }
        
        /**
         * \brief Setter for the opcode field.
         * 
         * \return uint8_t containing the value of the opcode field.
         */
        uint8_t opcode() const { return dns.opcode; }
        
        /**
         * \brief Setter for the authoritative answer field.
         * 
         * \return uint8_t containing the value of the authoritative 
         * answer field.
         */
        uint8_t authoritative_answer() const { return dns.aa; }
        
        /**
         * \brief Setter for the truncated field.
         * 
         * \return uint8_t containing the value of the truncated field.
         */
        uint8_t truncated() const { return dns.tc; }
        
        /**
         * \brief Setter for the recursion desired field.
         * 
         * \return uint8_t containing the value of the recursion
         * desired field.
         */
        uint8_t recursion_desired() const { return dns.rd; }
        
        /**
         * \brief Setter for the recursion available field.
         * 
         * \return uint8_t containing the value of the recursion
         * available field.
         */
        uint8_t recursion_available() const { return dns.ra; }
        
        /**
         * \brief Setter for the z desired field.
         * 
         * \return uint8_t containing the value of the z field.
         */
        uint8_t z() const { return dns.z; }
        
        /**
         * \brief Setter for the authenticated data field.
         * 
         * \return uint8_t containing the value of the authenticated
         * data field.
         */
        uint8_t authenticated_data() const { return dns.ad; }
        
        /**
         * \brief Setter for the checking disabled field.
         * 
         * \return uint8_t containing the value of the checking 
         * disabled field.
         */
        uint8_t checking_disabled() const { return dns.cd; }
        
        /**
         * \brief Setter for the rcode field.
         * 
         * \return uint8_t containing the value of the rcode field.
         */
        uint8_t rcode() const { return dns.rcode; }
        
        /**
         * \brief Setter for the questions field.
         * 
         * \return uint16_t containing the value of the questions field.
         */
        uint16_t questions_count() const { return Endian::be_to_host(dns.questions); }
        
        /**
         * \brief Setter for the answers field.
         * 
         * \return uint16_t containing the value of the answers field.
         */
        uint16_t answers_count() const { return Endian::be_to_host(dns.answers); }
        
        /**
         * \brief Setter for the authority field.
         * 
         * \return uint16_t containing the value of the authority field.
         */
        uint16_t authority_count() const { return Endian::be_to_host(dns.authority); }
        
        /**
         * \brief Setter for the additional field.
         * 
         * \return uint16_t containing the value of the additional field.
         */
        uint16_t additional_count() const { return Endian::be_to_host(dns.additional); }

        /**
         * \brief Getter for the PDU's type.
         *
         * \return Returns the PDUType corresponding to the PDU.
         */
        PDUType pdu_type() const { return PDU::DNS; }
        
        /** 
         * \brief The header's size
         */
        uint32_t header_size() const;

        // Setters
         
        /**
         * \brief Setter for the id field.
         * 
         * \param new_id The new id to be set.
         */
        void id(uint16_t new_id);
        
        /**
         * \brief Setter for the query response field.
         * 
         * \param new_qr The new qr to be set.
         */
        void type(QRType new_qr);
        
        /**
         * \brief Setter for the opcode field.
         * 
         * \param new_opcode The new opcode to be set.
         */
        void opcode(uint8_t new_opcode);
        
        /**
         * \brief Setter for the authoritative answer field.
         * 
         * \param new_aa The new authoritative answer field value to 
         * be set.
         */
        void authoritative_answer(uint8_t new_aa);
        
        /**
         * \brief Setter for the truncated field.
         * 
         * \param new_tc The new truncated field value to 
         * be set.
         */
        void truncated(uint8_t new_tc);
        
        /**
         * \brief Setter for the recursion desired field.
         * 
         * \param new_rd The new recursion desired value to 
         * be set.
         */
        void recursion_desired(uint8_t new_rd);
        
        /**
         * \brief Setter for the recursion available field.
         * 
         * \param new_ra The new recursion available value to 
         * be set.
         */
        void recursion_available(uint8_t new_ra);
        
        /**
         * \brief Setter for the z(reserved) field.
         * 
         * \param new_z The new z value to be set.
         */
        void z(uint8_t new_z);
        
        /**
         * \brief Setter for the authenticated data field.
         * 
         * \param new_ad The new authenticated data value to 
         * be set.
         */
        void authenticated_data(uint8_t new_ad);
        
        /**
         * \brief Setter for the checking disabled field.
         * 
         * \param new_z The new checking disabled value to be set.
         */
        void checking_disabled(uint8_t new_cd);
        
        /**
         * \brief Setter for the rcode field.
         * 
         * \param new_rcode The new rcode value to be set.
         */
        void rcode(uint8_t new_rcode);
        
        // Methods
        
        /**
         * \brief Add a query to perform.
         * 
         * \param query The query to be added.
         */
        void add_query(const Query &query);
        
        /**
         * \brief Add an answer resource record.
         * 
         * \param resource The resource to be added.
         */
        void add_answer(const Resource &resource);

        /**
         * \brief Add an authority resource record.
         * 
         * \param resource The resource to be added.
         */
        void add_authority(const Resource &resource);
        
        /**
         * \brief Add an additional resource record.
         * 
         * \param resource The resource to be added.
         */
        void add_additional(const Resource &resource);
        
        /**
         * \brief Getter for this PDU's DNS queries.
         * 
         * \return The query records in this PDU.
         */
        queries_type queries() const;
        
        /**
         * \brief Getter for this PDU's DNS answers
         * 
         * \return The answer records in this PDU.
         */
        resources_type answers() const;

        /**
         * \brief Getter for this PDU's DNS authority records.
         * 
         * \return The authority records in this PDU.
         */
        resources_type authority() const;

        /**
         * \brief Getter for this PDU's DNS additional records.
         * 
         * \return The additional records in this PDU.
         */
        resources_type additional() const;
        
        /**
         * \brief Encodes a domain name.
         *
         * This processes the input domain name and returns the encoded 
         * version. Each label in the original domain name will be 
         * prefixed with a byte that indicates the label's length. 
         * The null-terminator byte <b>will</b> be included in the encoded
         * string. No compression is performed.
         *
         * For example, given the input "www.example.com", the output would
         * be "\x03www\x07example\x03com\x00".
         * 
         * \param domain_name The domain name to encode.
         * \return The encoded domain name.
         */
        static std::string encode_domain_name(const std::string &domain_name);

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
        DNS *clone() const {
            return new DNS(*this);
        }
    private:
        TINS_BEGIN_PACK
        struct dnshdr {
            uint16_t id;
            #if TINS_IS_LITTLE_ENDIAN
                uint16_t 
                    rd:1,
                    tc:1,
                    aa:1,
                    opcode:4,
                    qr:1,
                    rcode:4,
                    cd:1,
                    ad:1,
                    z:1,
                    ra:1;
            #elif TINS_IS_BIG_ENDIAN
                uint16_t 
                    qr:1,
                    opcode:4,
                    aa:1,
                    tc:1,
                    rd:1,
                    ra:1,
                    z:1,
                    ad:1,
                    cd:1,
                    rcode:4;
            #endif
            uint16_t questions, answers,
                     authority, additional;
        } TINS_END_PACK;
        
        typedef std::list<Query> QueriesType;
        typedef std::vector<std::pair<uint32_t*, uint32_t> > sections_type;
        
        const uint8_t* compose_name(const uint8_t *ptr, char *out_ptr) const;
        void convert_records(const uint8_t *ptr, const uint8_t *end, resources_type &res) const;
        const uint8_t* find_section_end(const uint8_t *ptr, const uint32_t num_records) const;
        const uint8_t* find_dname_end(const uint8_t *ptr) const;
        void update_records(uint32_t &section_start, uint32_t num_records, uint32_t threshold, uint32_t offset);
        uint8_t *update_dname(uint8_t *ptr, uint32_t threshold, uint32_t offset);
        static void inline_convert_v4(uint32_t value, char *output);
        static bool contains_dname(uint16_t type);
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        void add_record(const Resource &resource, const sections_type &sections);
        
        dnshdr dns;
        byte_array records_data;
        uint32_t answers_idx, authority_idx, additional_idx;
    };
}

#endif // TINS_DNS_H

