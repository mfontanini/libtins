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

using std::string;
using std::list;

namespace Tins {

DNS::DNS() : PDU(255), extra_size(0) {
    std::memset(&dns, 0, sizeof(dns));
}

DNS::DNS(const uint8_t *buffer, uint32_t total_sz) : PDU(255), extra_size(0) {
    if(total_sz < sizeof(dnshdr))
        throw std::runtime_error("Not enough size for a DNS header in the buffer.");
    std::memcpy(&dns, buffer, sizeof(dnshdr));
    const uint8_t *end(buffer + total_sz);
    uint16_t nquestions(questions());
    buffer += sizeof(dnshdr);
    for(uint16_t i(0); i < nquestions; ++i) {
        const uint8_t *ptr(buffer);
        while(ptr < end && *ptr)
            ptr++;
        Query query;
        if((ptr + (sizeof(uint16_t) << 1)) >= end)
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

DNS::DNS(const DNS& rhs) : PDU(rhs) {
    copy_fields(&rhs);
}

DNS& DNS::operator=(const DNS& rhs) {
    free_list(ans);
    free_list(arity);
    free_list(addit);
    copy_fields(&rhs);
    copy_inner_pdu(rhs);
    return *this;
}

DNS::~DNS() {
    free_list(ans);
    free_list(arity);
    free_list(addit);
}

void DNS::free_list(ResourcesType &lst) {
    while(lst.size()) {
        delete lst.front();
        lst.pop_front();
    }
}

const uint8_t *DNS::build_resource_list(list<ResourceRecord*> &lst, const uint8_t *ptr, uint32_t &sz, uint16_t nrecs) {
    const uint8_t *ptr_end(ptr + sz);
    const uint8_t *parse_start(ptr);
    for(uint16_t i(0); i < nrecs; ++i) {
        const uint8_t *this_opt_start(ptr);
        if(ptr + sizeof(uint16_t) > ptr_end)
            throw std::runtime_error("Not enough size for a given resource.");
        std::auto_ptr<ResourceRecord> res;
        if((*ptr  & 0xc0)) {
            uint16_t offset(*reinterpret_cast<const uint16_t*>(ptr));
            offset = Utils::net_to_host_s(offset) & 0x3fff;
            res.reset(new OffsetedResourceRecord(Utils::net_to_host_s(offset)));
            ptr += sizeof(uint16_t);
        }
        else {
            const uint8_t *str_end(ptr), *end(ptr + sz);
            while(str_end < end && *str_end)
                str_end++;
            if(str_end == end)
                throw std::runtime_error("Not enough size for a resource domain name.");
            str_end++;
            res.reset(new NamedResourceRecord(string(ptr, str_end)));
            ptr = str_end;
        }
        if(ptr + sizeof(res->info) > ptr_end)
            throw std::runtime_error("Not enough size for a resource info.");
        std::memcpy(&res->info, ptr, sizeof(res->info));
        ptr += sizeof(res->info);
        if(ptr + sizeof(uint16_t) > ptr_end)
            throw std::runtime_error("Not enough size for resource data size.");

        // Store the option size.
        res->data.resize(
            Utils::net_to_host_s(*reinterpret_cast<const uint16_t*>(ptr))
        );
        ptr += sizeof(uint16_t);
        if(ptr + res->data.size() > ptr_end)
            throw std::runtime_error("Not enough size for resource data");
        if(contains_dname(res->info.type))
            std::copy(ptr, ptr + res->data.size(), res->data.begin());
        else
            *(uint32_t*)&res->data[0] = Utils::net_to_host_l(*(uint32_t*)ptr);
        
        ptr += res->data.size();
        extra_size += ptr - this_opt_start;
        lst.push_back(res.release());
    }
    sz -= ptr - parse_start;
    return ptr;
}

uint32_t DNS::header_size() const {
    return sizeof(dns) + extra_size;
}

void DNS::id(uint16_t new_id) {
    dns.id = Utils::net_to_host_s(new_id);
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
    return type == Utils::net_to_host_s(MX) || type == Utils::net_to_host_s(CNAME) ||
          type == Utils::net_to_host_s(PTR) || type == Utils::net_to_host_s(NS);
}

void DNS::add_query(const string &name, QueryType type, QueryClass qclass) {
    string new_str;
    parse_domain_name(name, new_str);
    
    queries.push_back(
        Query(new_str, 
        Utils::net_to_host_s(type), 
        Utils::net_to_host_s(qclass))
    );
    extra_size += new_str.size() + 1 + (sizeof(uint16_t) << 1);
    dns.questions = Utils::net_to_host_s(queries.size());
}

void DNS::add_query(const Query &query) {
    add_query(
        query.name, 
        static_cast<QueryType>(query.type), 
        static_cast<QueryClass>(query.qclass)
    );
}

void DNS::add_answer(const string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, ip);
    ans.push_back(res);
    dns.answers = Utils::net_to_host_s(ans.size());
}

void DNS::add_answer(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, const std::string &dname) {
    string new_str;
    parse_domain_name(dname, new_str);
    ResourceRecord *res = make_record(name, type, qclass, ttl, new_str);
    ans.push_back(res);
    dns.answers = Utils::net_to_host_s(ans.size());
}

void DNS::add_answer(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, const uint8_t *data, uint32_t sz) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, data, sz);
    ans.push_back(res);
    dns.answers = Utils::net_to_host_s(ans.size());
}

void DNS::add_authority(const string &name, QueryType type, 
  QueryClass qclass, uint32_t ttl, const uint8_t *data, uint32_t sz) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, data, sz);
    arity.push_back(res);
    dns.authority = Utils::net_to_host_s(arity.size());
}

void DNS::add_additional(const string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, ip);
    addit.push_back(res);
    dns.additional = Utils::net_to_host_s(addit.size());
}

DNS::ResourceRecord *DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ip = Utils::net_to_host_l(ip);
    return make_record(name, type, qclass, ttl, reinterpret_cast<uint8_t*>(&ip), sizeof(ip));
}

DNS::ResourceRecord *DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, const std::string &dname) {
    return make_record(name, type, qclass, ttl, reinterpret_cast<const uint8_t*>(dname.c_str()), dname.size() + 1);
}

DNS::ResourceRecord *DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, const uint8_t *ptr, uint32_t len) {
    string nm;
    parse_domain_name(name, nm);
    uint16_t index = find_domain_name(nm);
    ResourceRecord *res;
    if(index)
        res = new OffsetedResourceRecord(Utils::net_to_host_s(index), ptr, len);
    else
        res = new NamedResourceRecord(nm, ptr, len);
    res->info.type = Utils::net_to_host_s(type);
    res->info.qclass = Utils::net_to_host_s(qclass);
    res->info.ttl = Utils::net_to_host_l(ttl);
    extra_size += res->size();
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
        if((*it)->matches(dname))
            break;
        out += (*it)->size();
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
        buffer += (*it)->write(buffer);
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

uint32_t DNS::build_suffix_map(uint32_t index, const list<ResourceRecord*> &lst) {
    const string *str;
    for(ResourcesType::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        str = (*it)->dname_pointer();
        if(str) {
            add_suffix(index, (uint8_t*)str->c_str(), str->size());
            index += str->size() + 1;
        }
        else
            index += sizeof(uint16_t);
        index += sizeof(ResourceRecord::Info) + sizeof(uint16_t);
        uint32_t sz((*it)->data_size());
        const uint8_t *ptr = (*it)->data_pointer();
        if((*it)->info.type == Utils::net_to_host_s(MX)) {
            ptr += 2;
            sz -= 2;
            index += 2;
        }
        if(contains_dname((*it)->info.type))
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
            uint16_t index = Utils::net_to_host_s(*((uint16_t*)(ptr + i)));
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
            if(i + suff_sz < sz)
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
        if((str_ptr = (*it)->dname_pointer())) 
            compose_name(reinterpret_cast<const uint8_t*>(str_ptr->c_str()), str_ptr->size(), dname);
        else {
            uint16_t offset = static_cast<OffsetedResourceRecord*>(*it)->offset;
            compose_name((uint8_t*)&offset, 2, dname);
        }
        ptr = (*it)->data_pointer();
        sz = (*it)->data_size();
        if(sz == 4)
            addr = Utils::ip_to_string(*(uint32_t*)ptr);
        else {
            if((*it)->info.type ==  Utils::net_to_host_s(MX)) {
                ptr += 2;
                sz -= 2;
            }
            compose_name(ptr, sz, addr);
        }
        res.push_back(
            Resource(dname, addr, Utils::net_to_host_s((*it)->info.type), 
            Utils::net_to_host_s((*it)->info.qclass), Utils::net_to_host_l((*it)->info.ttl))
        );
    }
}

list<DNS::Query> DNS::dns_queries() const { 
    list<Query> output;
    for(std::list<Query>::const_iterator it(queries.begin()); it != queries.end(); ++it) {
        string dn;
        unparse_domain_name(it->name, dn);
        output.push_back(Query(dn, Utils::net_to_host_s(it->type), Utils::net_to_host_s(it->qclass)));
    }
    return output;
}

list<DNS::Resource> DNS::dns_answers() {
    list<Resource> res;
    convert_resources(ans, res);
    return res;
}

void DNS::copy_fields(const DNS *other) {
    std::memcpy(&dns, &other->dns, sizeof(dns));
    extra_size = other->extra_size;
    queries = other->queries;
    copy_list(other->ans, ans);
    copy_list(other->arity, arity);
    copy_list(other->addit, addit);
}

void DNS::copy_list(const ResourcesType &from, ResourcesType &to) const {
    for(ResourcesType::const_iterator it(from.begin()); it != from.end(); ++it) {
        to.push_back((*it)->clone());
    }
}

// ResourceRecord

uint32_t DNS::ResourceRecord::write(uint8_t *buffer) const {
    const uint32_t sz(do_write(buffer));
    buffer += sz;
    std::memcpy(buffer, &info, sizeof(info));
    buffer += sizeof(info);
    *((uint16_t*)buffer) = Utils::net_to_host_s(data.size());
    buffer += sizeof(uint16_t);
    std::copy(data.begin(), data.end(), buffer);
    return sz + sizeof(info) + sizeof(uint16_t) + data.size();
}

DNS::ResourceRecord *DNS::OffsetedResourceRecord::clone() const {
    return new OffsetedResourceRecord(*this);
}

DNS::ResourceRecord *DNS::NamedResourceRecord::clone() const {
    return new NamedResourceRecord(*this);
}
}
