/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
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
#include "utils.h"

namespace Tins {
    class DNS : public PDU {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DNS;
    
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
        struct Query {
            std::string name;
            uint16_t type, qclass;
            
            Query(const std::string &nm, uint16_t t, uint16_t c) :
                name(nm), type(t), qclass(c) {}
            Query() {}
        };
        
        /**
         * \brief Struct that represent DNS resource records.
         */
        struct Resource {
            std::string dname, addr;
            uint16_t type, qclass;
            uint32_t ttl;
            
            Resource(const std::string &nm, const std::string &ad, 
                     uint16_t t, uint16_t c, uint32_t tt) :
                dname(nm), addr(ad), type(t), qclass(c), ttl(tt) {}
        };
        
        typedef std::list<Query> queries_type;
        typedef std::list<Resource> resources_type;
        
        /**
         * \brief Default constructor.
         * 
         * This constructor initializes every field to 0.
         */
        DNS();
        
        /**
         * \brief Destructor.
         */
        ~DNS();
        
        /**
         * \brief Constructor which creates a DNS object from a buffer 
         * and adds all identifiable PDUs found in the buffer as 
         * children of this one.
         * \param buffer The buffer from which this PDU will be 
         * constructed.
         * \param total_sz The total size of the buffer.
         */
        DNS(const uint8_t *buffer, uint32_t total_sz);
        
        /**
         * \brief Copy constructor.
         */
        DNS(const DNS& rhs);
        
        /**
         * \brief Copy assignment operator.
         */
        DNS& operator=(const DNS& rhs);
        
        // Getters
        
        /**
         * \brief Setter for the id field.
         * 
         * \return uint16_t containing the value of the id field.
         */
        uint16_t id() const { return Utils::be_to_host(dns.id); }
        
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
        uint16_t questions() const { return Utils::be_to_host(dns.questions); }
        
        /**
         * \brief Setter for the answers field.
         * 
         * \return uint16_t containing the value of the answers field.
         */
        uint16_t answers() const { return Utils::be_to_host(dns.answers); }
        
        /**
         * \brief Setter for the authority field.
         * 
         * \return uint16_t containing the value of the authority field.
         */
        uint16_t authority() const { return Utils::be_to_host(dns.authority); }
        
        /**
         * \brief Setter for the additional field.
         * 
         * \return uint16_t containing the value of the additional field.
         */
        uint16_t additional() const { return Utils::be_to_host(dns.additional); }

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
         * \param name The name to be resolved.
         * \param type The type of this query.
         * \param qclass The class of this query.
         */
        void add_query(const std::string &name, QueryType type, QueryClass qclass);
        
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
        void add_answer(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, IPv4Address ip);
                        
        /**
         * \brief Add a query response.
         * 
         * \param name The resolved name.
         * \param type The type of this answer.
         * \param qclass The class of this answer.
         * \param ttl The time-to-live of this answer.
         * \param dname The domain of the resolved name.
         */
        void add_answer(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, const std::string &dname);
                        
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
        void add_answer(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, const uint8_t *data, uint32_t sz);
        
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
        void add_authority(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, const uint8_t *data, uint32_t sz);
        
        /**
         * \brief Add an additional record.
         * 
         * \param name The resolved name.
         * \param type The type of this record.
         * \param qclass The class of this record.
         * \param ttl The time-to-live of this record.
         * \param ip The ip address of the resolved name.
         */
        void add_additional(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, uint32_t ip);
                        
        
        /**
         * \brief Getter for this PDU's DNS queries.
         * \return std::list<Query> containing the queries in this
         * record.
         */
        queries_type dns_queries() const;
        
        /**
         * \brief Getter for this PDU's DNS answers
         * \return std::list<Resource> containing the answers in this
         * record.
         */
        resources_type dns_answers();
        
        /**
         * \sa PDU::clone_pdu
         */
        PDU *clone_pdu() const {
            return do_clone_pdu<DNS>();
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
        
        struct ResourceRecord {
            struct Info {
                uint16_t type, qclass;
                uint32_t ttl;
            } __attribute__((packed)) info;

            std::vector<uint8_t> data;
            
            ResourceRecord(const uint8_t *d = 0, uint16_t len = 0)  {
                if(d && len)
                    data.assign(d, d + len);
            }
            
            virtual ~ResourceRecord() {}
            virtual ResourceRecord *clone() const = 0;
            uint32_t write(uint8_t *buffer) const;
            virtual uint32_t do_write(uint8_t *buffer) const = 0;
            virtual uint32_t size() const = 0;
            virtual bool matches(const std::string &dname) { return false; }
            uint32_t data_size() const {
                return data.size();
            }
            const uint8_t *data_pointer() const {
                return &data[0];
            }
            virtual const std::string *dname_pointer() const { return 0; }
        };
        
        struct OffsetedResourceRecord : public ResourceRecord {
            uint16_t offset;
            
            OffsetedResourceRecord(uint16_t off, const uint8_t *data = 0, uint16_t len = 0) 
              : ResourceRecord(data,len), offset(off | 0xc0) {}
            
            uint32_t do_write(uint8_t *buffer) const {
                std::memcpy(buffer, &offset, sizeof(offset));
                return sizeof(offset);
            }
            uint32_t size() const { 
                return sizeof(ResourceRecord::info) + sizeof(offset) + data.size() + sizeof(uint16_t); 
            }
            ResourceRecord *clone() const;
        };
        
        struct NamedResourceRecord : public ResourceRecord {
            std::string name;
            
            NamedResourceRecord(const std::string &nm,  const uint8_t *data = 0, uint16_t len = 0) 
              : ResourceRecord(data,len), name(nm) {}
            
            uint32_t do_write(uint8_t *buffer) const {
                std::memcpy(buffer, name.c_str(), name.size() + 1);
                return name.size() + 1;
            }
            
            uint32_t size() const { 
                return sizeof(ResourceRecord::info) + name.size() + 1 + data.size() + sizeof(uint16_t); 
            }
            
            bool matches(const std::string &dname) { 
                return dname == name; 
            }
            
            const std::string *dname_pointer() const {
                return &name;
            }
            ResourceRecord *clone() const;
        };
        
        typedef std::map<uint16_t, std::string> SuffixMap;
        typedef std::map<uint16_t, uint16_t> SuffixIndices;
        typedef std::list<ResourceRecord*> ResourcesType;
        typedef std::list<Query> QueriesType;
        
        const uint8_t *build_resource_list(std::list<ResourceRecord*> &lst, const uint8_t *ptr, uint32_t &sz, uint16_t nrecs);
        uint32_t find_domain_name(const std::string &dname);
        bool find_domain_name(const std::string &dname, const ResourcesType &lst, uint16_t &out);
        void parse_domain_name(const std::string &dn, std::string &out) const;
        void unparse_domain_name(const std::string &dn, std::string &out) const;
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        uint8_t *serialize_list(const ResourcesType &lst, uint8_t *buffer) const;
        void compose_name(const uint8_t *ptr, uint32_t sz, std::string &out);
        void convert_resources(const ResourcesType &lst, std::list<Resource> &res);
        ResourceRecord *make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip);
        ResourceRecord *make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, const std::string &dname);
        ResourceRecord *make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, const uint8_t *ptr, uint32_t len);
        void add_suffix(uint32_t index, const uint8_t *data, uint32_t sz);
        uint32_t build_suffix_map(uint32_t index, const ResourcesType &lst);
        uint32_t build_suffix_map(uint32_t index, const QueriesType &lst);
        void build_suffix_map();
        void copy_list(const ResourcesType &from, ResourcesType &to) const;
        bool contains_dname(uint16_t type);
        void free_list(ResourcesType &lst);
        
        void copy_fields(const DNS *other);
        
        dnshdr dns;
        uint32_t extra_size;
        std::list<Query> queries;
        std::list<ResourceRecord*> ans, arity, addit;
        SuffixMap suffixes;
        SuffixIndices suffix_indices;
    };
};

#endif // TINS_DNS_H

