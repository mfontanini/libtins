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

#ifndef TINS_DNS_H
#define TINS_DNS_H

#include <stdint.h>
#include <list>
#include <vector>
#include <cstring>
#include <string>
#include <map>
#include "pdu.h"
#include "endianness.h"
#include "dns_record.h"

namespace Tins {
    class IPv4Address;
    class IPv6Address;
    
    /**
     * \class DNS
     * \brief Represents a DNS PDU.
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
            Resource(const std::string &nm, const std::string &ad, 
              uint16_t t, uint16_t c, uint32_t tt) 
            : dname_(nm), addr_(ad), type_(t), qclass_(c), ttl_(tt) {}
            
            Resource() : type_(), qclass_(), ttl_() {}
            
            /**
             * \brief Getter for the dname field.
             * 
             * This returns the domain name for which this record 
             * provides an answer.
             */
            const std::string &dname() const { return dname_; }
            
            /**
             * Getter for the type field.
             */
            const std::string &data() const { return addr_; }
            
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
        private:
            std::string dname_, addr_;
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
         * \brief Constructor which creates a DNS object from a buffer.
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
         * \brief Add a query response.
         * 
         * \param name The resolved name.
         * \param type The type of this answer.
         * \param qclass The class of this answer.
         * \param ttl The time-to-live of this answer.
         * \param ip The ip address of the resolved name.
         */
        void add_answer(const std::string &name, 
          const DNSResourceRecord::info &info, address_type ip);
          
        /**
         * \brief Add a query response.
         * 
         * \param name The resolved name.
         * \param type The type of this answer.
         * \param qclass The class of this answer.
         * \param ttl The time-to-live of this answer.
         * \param ip The ip address of the resolved name.
         */
        void add_answer(const std::string &name, 
          const DNSResourceRecord::info &info, address_v6_type ip);
                        
        /**
         * \brief Add a query response.
         * 
         * \param name The resolved name.
         * \param type The type of this answer.
         * \param qclass The class of this answer.
         * \param ttl The time-to-live of this answer.
         * \param dname The domain of the resolved name.
         */
        void add_answer(const std::string &name, 
          const DNSResourceRecord::info &info, const std::string &dname);
                        
        /**
         * \brief Add a query response.
         * 
         * \param name The resolved name.
         * \param type The type of this answer.
         * \param qclass The class of this answer.
         * \param ttl The time-to-live of this answer.
         * \param data The data of this option.
         * \param sz The size of the data.
         */
        void add_answer(const std::string &name, 
          const DNSResourceRecord::info &info, const uint8_t *data, uint32_t sz);
        
        /**
         * \brief Add an authority record.
         * 
         * \param name The resolved name.
         * \param type The type of this record.
         * \param qclass The class of this record.
         * \param ttl The time-to-live of this record.
         * \param data The data of this option.
         * \param sz The size of the data.
         */
        void add_authority(const std::string &name, 
          const DNSResourceRecord::info &info, const uint8_t *data, uint32_t sz);
        
        /**
         * \brief Add an additional record.
         * 
         * \param name The resolved name.
         * \param type The type of this record.
         * \param qclass The class of this record.
         * \param ttl The time-to-live of this record.
         * \param ip The ip address of the resolved name.
         */
        void add_additional(const std::string &name, 
          const DNSResourceRecord::info &info, uint32_t ip);
                        
        
        /**
         * \brief Getter for this PDU's DNS queries.
         * \return std::list<Query> containing the queries in this
         * record.
         */
        queries_type queries() const;
        
        /**
         * \brief Getter for this PDU's DNS answers
         * \return std::list<Resource> containing the answers in this
         * record.
         */
        resources_type answers() const;
        
        /**
         * \sa PDU::clone
         */
        DNS *clone() const {
            return new DNS(*this);
        }
        
        /**
         * Helper function to create a resource record information
         * 
         * \param type The type of the query.
         * \param qclass The class of the query.
         * \param ttl The time-to-live of the query.
         */
        static DNSResourceRecord::info make_info(QueryType type, QueryClass qclass, uint32_t ttl) {
            return DNSResourceRecord::info((uint16_t)type, (uint16_t)qclass, ttl);
        }
    private:
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
        } __attribute__((packed));
        
        typedef std::map<uint16_t, std::string> SuffixMap;
        typedef std::map<uint16_t, uint16_t> SuffixIndices;
        typedef std::list<DNSResourceRecord> ResourcesType;
        typedef std::list<Query> QueriesType;
        
        const uint8_t *build_resource_list(ResourcesType &lst, const uint8_t *ptr, uint32_t &sz, uint16_t nrecs);
        uint32_t find_domain_name(const std::string &dname);
        bool find_domain_name(const std::string &dname, const ResourcesType &lst, uint16_t &out);
        void parse_domain_name(const std::string &dn, std::string &out) const;
        void unparse_domain_name(const std::string &dn, std::string &out) const;
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        uint8_t *serialize_list(const ResourcesType &lst, uint8_t *buffer) const;
        void compose_name(const uint8_t *ptr, uint32_t sz, std::string &out) const;
        void convert_resources(const ResourcesType &lst, std::list<Resource> &res) const;
        DNSResourceRecord make_record(const std::string &name, const DNSResourceRecord::info &info, uint32_t ip);
        DNSResourceRecord make_record(const std::string &name, const DNSResourceRecord::info &info, const std::string &dname);
        DNSResourceRecord make_record(const std::string &name, const DNSResourceRecord::info &info, const uint8_t *ptr, uint32_t len);
        void add_suffix(uint32_t index, const uint8_t *data, uint32_t sz) const;
        uint32_t build_suffix_map(uint32_t index, const ResourcesType &lst) const;
        uint32_t build_suffix_map(uint32_t index, const QueriesType &lst) const;
        void build_suffix_map() const ;
        static bool contains_dname(uint16_t type);
        
        dnshdr dns;
        uint32_t extra_size;
        std::list<Query> queries_;
        ResourcesType ans, arity, addit;
        mutable SuffixMap suffixes;
        mutable SuffixIndices suffix_indices;
    };
};

#endif // TINS_DNS_H

