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

#include <utility>
#include <stdexcept>
#include <cassert>
#include <memory>
#include "dns.h"
#include "ip_address.h"

using std::string;
using std::list;

namespace Tins {

DNS::DNS() : extra_size(0) {
    std::memset(&dns, 0, sizeof(dns));
}

DNS::DNS(const uint8_t *buffer, uint32_t total_sz) : extra_size(0) {
    if(total_sz < sizeof(dnshdr))
        throw std::runtime_error("Not enough size for a DNS header in the buffer.");
    std::memcpy(&dns, buffer, sizeof(dnshdr));
    const uint8_t *end(buffer + total_sz);
    uint16_t nquestions(questions());
    buffer += sizeof(dnshdr);
    total_sz -= sizeof(dnshdr);
    for(uint16_t i(0); i < nquestions; ++i) {
        const uint8_t *ptr(buffer);
        while(ptr < end && *ptr)
            ptr++;
        Query query;
        if((ptr + (sizeof(uint16_t) * 2)) >= end)
            throw std::runtime_error("Not enough size for a given query.");
        query.name = string(buffer, ptr);
        ptr++;
        const uint16_t *opt_ptr = reinterpret_cast<const uint16_t*>(ptr);
        query.type = *(opt_ptr++);
        query.qclass = *(opt_ptr++);
        queries.push_back(query);
        total_sz -= reinterpret_cast<const uint8_t*>(opt_ptr) - buffer;
        extra_size += reinterpret_cast<const uint8_t*>(opt_ptr) - buffer;
        buffer = reinterpret_cast<const uint8_t*>(opt_ptr);
    }
    buffer = build_resource_list(ans, buffer, total_sz, answers());
    buffer = build_resource_list(arity, buffer, total_sz, authority());
    build_resource_list(addit, buffer, total_sz, additional());
}

const uint8_t *DNS::build_resource_list(ResourcesType &lst, const uint8_t *ptr, uint32_t &sz, uint16_t nrecs) {
    const uint8_t *ptr_end(ptr + sz);
    const uint8_t *parse_start(ptr);
    for(uint16_t i(0); i < nrecs; ++i) {
        const uint8_t *this_opt_start(ptr);
        if(ptr + sizeof(uint16_t) > ptr_end)
            throw std::runtime_error("Not enough size for a given resource.");
        lst.push_back(DNSResourceRecord(ptr, ptr_end - ptr));
        ptr += lst.back().size();
        extra_size += ptr - this_opt_start;
        
    }
    sz -= ptr - parse_start;
    return ptr;
}

uint32_t DNS::header_size() const {
    return sizeof(dns) + extra_size;
}

void DNS::id(uint16_t new_id) {
    dns.id = Endian::host_to_be(new_id);
}

void DNS::type(QRType new_qr) {
    dns.qr = new_qr;
}

void DNS::opcode(uint8_t new_opcode) {
    dns.opcode = new_opcode;
}

void DNS::authoritative_answer(uint8_t new_aa) {
    dns.aa = new_aa;
}

void DNS::truncated(uint8_t new_tc) {
    dns.tc = new_tc;
}

void DNS::recursion_desired(uint8_t new_rd) {
    dns.rd = new_rd;
}

void DNS::recursion_available(uint8_t new_ra) {
    dns.ra = new_ra;
}

void DNS::z(uint8_t new_z) {
    dns.z = new_z;
}

void DNS::authenticated_data(uint8_t new_ad) {
    dns.ad = new_ad;
}

void DNS::checking_disabled(uint8_t new_cd) {
    dns.cd = new_cd;
}

void DNS::rcode(uint8_t new_rcode) {
    dns.rcode = new_rcode;
}

bool DNS::contains_dname(uint16_t type) {
    type = Endian::be_to_host(type);
    return type == MX || type == CNAME ||
          type == PTR || type == NS;
}

void DNS::add_query(const string &name, QueryType type, QueryClass qclass) {
    string new_str;
    parse_domain_name(name, new_str);
    
    queries.push_back(
        Query(new_str, 
        Endian::host_to_be<uint16_t>(type), 
        Endian::host_to_be<uint16_t>(qclass))
    );
    extra_size += new_str.size() + 1 + (sizeof(uint16_t) << 1);
    dns.questions = Endian::host_to_be<uint16_t>(queries.size());
}

void DNS::add_query(const Query &query) {
    add_query(
        query.name, 
        static_cast<QueryType>(query.type), 
        static_cast<QueryClass>(query.qclass)
    );
}

void DNS::add_answer(const string &name, QueryType type, QueryClass qclass, uint32_t ttl, IPv4Address ip) {
    ans.push_back(make_record(name, type, qclass, ttl, Endian::host_to_be((uint32_t)ip)));
    dns.answers = Endian::host_to_be<uint16_t>(ans.size());
}

void DNS::add_answer(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, const std::string &dname) {
    string new_str;
    parse_domain_name(dname, new_str);
    DNSResourceRecord res = make_record(name, type, qclass, ttl, new_str);
    ans.push_back(res);
    dns.answers = Endian::host_to_be<uint16_t>(ans.size());
}

void DNS::add_answer(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, const uint8_t *data, uint32_t sz) {
    ans.push_back(make_record(name, type, qclass, ttl, data, sz));
    dns.answers = Endian::host_to_be<uint16_t>(ans.size());
}

void DNS::add_authority(const string &name, QueryType type, 
  QueryClass qclass, uint32_t ttl, const uint8_t *data, uint32_t sz) {
    arity.push_back(make_record(name, type, qclass, ttl, data, sz));
    dns.authority = Endian::host_to_be<uint16_t>(arity.size());
}

void DNS::add_additional(const string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    addit.push_back(make_record(name, type, qclass, ttl, ip));
    dns.additional = Endian::host_to_be<uint16_t>(addit.size());
}

DNSResourceRecord DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ip = Endian::host_to_be(ip);
    return make_record(name, type, qclass, ttl, reinterpret_cast<uint8_t*>(&ip), sizeof(ip));
}

DNSResourceRecord DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, const std::string &dname) {
    return make_record(name, type, qclass, ttl, reinterpret_cast<const uint8_t*>(dname.c_str()), dname.size() + 1);
}

DNSResourceRecord DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, const uint8_t *ptr, uint32_t len) {
    string nm;
    parse_domain_name(name, nm);
    uint16_t index = find_domain_name(nm);
    DNSResourceRecord res;
    if(index)
        res = make_offseted_record(Endian::host_to_be(index), ptr, len);
    else
        res = make_named_record(nm, ptr, len);
    res.info().type = Endian::host_to_be<uint16_t>(type);
    res.info().qclass = Endian::host_to_be<uint16_t>(qclass);
    res.info().ttl = Endian::host_to_be(ttl);
    extra_size += res.size();
    return res;
}

uint32_t DNS::find_domain_name(const std::string &dname) {
    uint16_t index(sizeof(dnshdr));
    list<Query>::const_iterator it(queries.begin());
    for(; it != queries.end() && it->name != dname; ++it)
        index += it->name.size() + 1 + (sizeof(uint16_t) << 1);
    if(it != queries.end() ||
       find_domain_name(dname, ans, index) || 
       find_domain_name(dname, arity, index) || 
       find_domain_name(dname, addit, index))
        return index;
    else
        return 0;
}

bool DNS::find_domain_name(const std::string &dname, const ResourcesType &lst, uint16_t &out) {
    ResourcesType::const_iterator it(lst.begin());
    while(it != lst.end()) {
        if(it->matches(dname))
            break;
        out += it->size();
        ++it;
    }
    return it != lst.end();
}

void DNS::parse_domain_name(const std::string &dn, std::string &out) const {
    size_t last_index(0), index;
    while((index = dn.find('.', last_index+1)) != string::npos) {
        out.push_back(index - last_index);
        out.append(dn.begin() + last_index, dn.begin() + index);
        last_index = index + 1; //skip dot
    }
    out.push_back(dn.size() - last_index);
    out.append(dn.begin() + last_index, dn.end());
}

void DNS::unparse_domain_name(const std::string &dn, std::string &out) const {
    if(dn.size()) {
        uint32_t index(1), len(dn[0]);
        while(index + len < dn.size() && len) {
            if(index != 1)
                out.push_back('.');
            out.append(dn.begin() + index, dn.begin() + index + len);
            index += len;
            if(index < dn.size() - 1)
                len = dn[index];
            index++;
        }
        if(index < dn.size()) {
            out.push_back('.');
            out.append(dn.begin() + index, dn.end());
        }
    }
}

void DNS::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(dns) + extra_size);
    std::memcpy(buffer, &dns, sizeof(dns)); 
    buffer += sizeof(dns);
    for(list<Query>::const_iterator it(queries.begin()); it != queries.end(); ++it) {
        std::memcpy(buffer, it->name.c_str(), it->name.size() + 1);
        buffer += it->name.size() + 1;
        *((uint16_t*)buffer) = it->type;
        buffer += sizeof(uint16_t);
        *((uint16_t*)buffer) = it->qclass;
        buffer += sizeof(uint16_t);
    }
    buffer = serialize_list(ans, buffer);
    buffer = serialize_list(arity, buffer);
    buffer = serialize_list(addit, buffer);
}

uint8_t *DNS::serialize_list(const ResourcesType &lst, uint8_t *buffer) const {
    for(ResourcesType::const_iterator it(lst.begin()); it != lst.end(); ++it)
        buffer += it->write(buffer);
    return buffer;
}

void DNS::add_suffix(uint32_t index, const uint8_t *data, uint32_t sz) {
    uint32_t i(0), suff_sz(data[0]);
    SuffixMap::iterator it;
    while((i + suff_sz + 1 <= sz || (suff_sz == 0xc0 && i + 1 < sz)) && suff_sz) {
        if((suff_sz & 0xc0)) {
            if((it = suffixes.find(data[i+1])) != suffixes.end())
                suffix_indices[index + i] = data[i+1];
            i += sizeof(uint16_t);
        }
        else {
            ++i;
            suffixes.insert(std::make_pair(index + i - 1, string(data + i, data + i + suff_sz)));
            i += suff_sz;
        }        
        if(i < sz)
            suff_sz = data[i];
    }
}

uint32_t DNS::build_suffix_map(uint32_t index, const ResourcesType &lst) {
    const string *str;
    for(ResourcesType::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        str = it->dname();
        if(str) {
            add_suffix(index, (uint8_t*)str->c_str(), str->size());
            index += str->size() + 1;
        }
        else
            index += sizeof(uint16_t);
        index += sizeof(DNSResourceRecord::Info) + sizeof(uint16_t);
        uint32_t sz(it->data_size());
        const uint8_t *ptr = it->data_ptr();
        if(Endian::be_to_host(it->info().type) == MX) {
            ptr += 2;
            sz -= 2;
            index += 2;
        }
        if(contains_dname(it->info().type))
            add_suffix(index, ptr, sz);
        index += sz;
    }
    return index;
}

uint32_t DNS::build_suffix_map(uint32_t index, const list<Query> &lst) {
    for(list<Query>::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        add_suffix(index, (uint8_t*)it->name.c_str(), it->name.size());
        index += it->name.size() + 1 + (sizeof(uint16_t) << 1);
    }
    return index;
}

void DNS::build_suffix_map() {
    uint32_t index(sizeof(dnshdr));
    index = build_suffix_map(index, queries);
    index = build_suffix_map(index, ans);
    index = build_suffix_map(index, arity);
    build_suffix_map(index, addit);
}

void DNS::compose_name(const uint8_t *ptr, uint32_t sz, std::string &out) {
    uint32_t i(0);
    while(i < sz) {
        if(i && ptr[i])
            out.push_back('.');
        if((ptr[i] & 0xc0)) {
            uint16_t index = Endian::be_to_host(*((uint16_t*)(ptr + i)));
            index &= 0x3fff;
            SuffixMap::iterator it(suffixes.find(index));
            SuffixIndices::iterator suff_it(suffix_indices.find(index));
            //assert(it != suffixes.end() && suff_it == suffix_indices.end());
            if(it == suffixes.end() || suff_it == suffix_indices.end())
                throw std::runtime_error("Malformed DNS packet");
            bool first(true);
            do {
                if(it != suffixes.end()) {
                    if(!first)
                        out.push_back('.');
                    first = false;
                    out += it->second;
                    index += it->second.size() + 1;
                }
                else
                    index = suff_it->second;
                it = suffixes.find(index);
                if(it == suffixes.end())
                    suff_it = suffix_indices.find(index);
                
            } while(it != suffixes.end() || suff_it != suffix_indices.end());
            break;
        }
        else {
            uint8_t suff_sz(ptr[i]);
            i++;
            if(i + suff_sz <= sz)
                out.append(ptr + i, ptr + i + suff_sz);
            i += suff_sz;
        }
    }
}

void DNS::convert_resources(const ResourcesType &lst, std::list<Resource> &res) {
    if(!suffixes.size())
        build_suffix_map();
    const string *str_ptr;
    const uint8_t *ptr;
    uint32_t sz;
    for(ResourcesType::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        string dname, addr;
        if(it->has_domain_name() && (str_ptr = it->dname())) 
            compose_name(reinterpret_cast<const uint8_t*>(str_ptr->c_str()), str_ptr->size(), dname);
        else {
            uint16_t offset = it->offset();
            compose_name((uint8_t*)&offset, 2, dname);
        }
        ptr = it->data_ptr();
        sz = it->data_size();
        if(sz == 4)
            addr = IPv4Address(*(uint32_t*)ptr).to_string();
        else {
            if(Endian::be_to_host(it->info().type) ==  MX) {
                ptr += 2;
                sz -= 2;
            }
            compose_name(ptr, sz, addr);
        }
        res.push_back(
            Resource(dname, addr, Endian::be_to_host(it->info().type), 
              Endian::host_to_be(it->info().qclass), Endian::be_to_host(it->info().ttl)
            )
        );
    }
}

DNS::queries_type DNS::dns_queries() const { 
    queries_type output;
    for(std::list<Query>::const_iterator it(queries.begin()); it != queries.end(); ++it) {
        string dn;
        unparse_domain_name(it->name, dn);
        output.push_back(Query(dn, Endian::be_to_host(it->type), Endian::be_to_host(it->qclass)));
    }
    return output;
}

DNS::resources_type DNS::dns_answers() {
    resources_type res;
    convert_resources(ans, res);
    return res;
}
}
