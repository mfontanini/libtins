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

#include <iostream> //borrame
#include <utility>
#include <cassert>
#include "dns.h"

using std::string;
using std::list;


Tins::DNS::DNS() : PDU(255), extra_size(0) {
    std::memset(&dns, 0, sizeof(dns));
}

Tins::DNS::~DNS() {
    free_list(ans);
    free_list(arity);
    free_list(addit);
}

void Tins::DNS::free_list(std::list<ResourceRecord*> &lst) {
    while(lst.size()) {
        delete lst.front();
        lst.pop_front();
    }
}

uint32_t Tins::DNS::header_size() const {
    return sizeof(dns) + extra_size;
}

void Tins::DNS::id(uint16_t new_id) {
    dns.id = new_id;
}

void Tins::DNS::type(QRType new_qr) {
    dns.qr = new_qr;
}

void Tins::DNS::opcode(uint8_t new_opcode) {
    dns.opcode = new_opcode;
}

void Tins::DNS::authoritative_answer(uint8_t new_aa) {
    dns.aa = new_aa;
}

void Tins::DNS::truncated(uint8_t new_tc) {
    dns.tc = new_tc;
}

void Tins::DNS::recursion_desired(uint8_t new_rd) {
    dns.rd = new_rd;
}

void Tins::DNS::recursion_available(uint8_t new_ra) {
    dns.ra = new_ra;
}

void Tins::DNS::z(uint8_t new_z) {
    dns.z = new_z;
}

void Tins::DNS::authenticated_data(uint8_t new_ad) {
    dns.ad = new_ad;
}

void Tins::DNS::checking_disabled(uint8_t new_cd) {
    dns.cd = new_cd;
}

void Tins::DNS::rcode(uint8_t new_rcode) {
    dns.rcode = new_rcode;
}

void Tins::DNS::add_query(const string &name, QueryType type, QueryClass qclass) {
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

void Tins::DNS::add_answer(const string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, ip);
    ans.push_back(res);
    dns.answers = Utils::net_to_host_s(ans.size());
}

void Tins::DNS::add_authority(const string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, ip);
    arity.push_back(res);
    dns.authority = Utils::net_to_host_s(arity.size());
}

void Tins::DNS::add_additional(const string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, ip);
    addit.push_back(res);
    dns.additional = Utils::net_to_host_s(addit.size());
}

Tins::DNS::ResourceRecord *Tins::DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    string nm;
    parse_domain_name(name, nm);
    uint16_t index = find_domain_name(nm);
    ResourceRecord *res;
    ip = Utils::net_to_host_l(ip);
    if(index)
        res = new OffsetedResourceRecord<4>(Utils::net_to_host_s(index), (uint8_t*)&ip);
    else
        res = new NamedResourceRecord<4>(nm, (uint8_t*)&ip);
    res->info.type = Utils::net_to_host_s(type);
    res->info.qclass = Utils::net_to_host_s(qclass);
    res->info.ttl = Utils::net_to_host_l(ttl);
    extra_size += res->size();
    return res;
}

uint32_t Tins::DNS::find_domain_name(const std::string &dname) {
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

bool Tins::DNS::find_domain_name(const std::string &dname, const std::list<ResourceRecord*> &lst, uint16_t &out) {
    list<ResourceRecord*>::const_iterator it(lst.begin());
    while(it != lst.end()) {
        if((*it)->matches(dname))
            break;
        out += (*it)->size();
        ++it;
    }
    return it != lst.end();
}

void Tins::DNS::parse_domain_name(const std::string &dn, std::string &out) const {
    size_t last_index(0), index;
    while((index = dn.find('.', last_index+1)) != string::npos) {
        out.push_back(index - last_index);
        out.append(dn.begin() + last_index, dn.begin() + index);
        last_index = index + 1; //skip dot
    }
    out.push_back(dn.size() - last_index);
    out.append(dn.begin() + last_index, dn.end());
}

void Tins::DNS::unparse_domain_name(const std::string &dn, std::string &out) const {
    if(dn.size()) {
        uint32_t index(1), len(dn[0]);
        while(index + len < dn.size() && len) {
            out.append(dn.begin() + index, dn.begin() + index + len);
            out.push_back('.');
            index += len;
            if(index < dn.size() - 1)
                len = dn[index];
            index++;
        }
        if(index < dn.size())
            out.append(dn.begin() + index, dn.end());
    }
}

void Tins::DNS::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
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

uint8_t *Tins::DNS::serialize_list(const std::list<ResourceRecord*> &lst, uint8_t *buffer) const {
    for(list<ResourceRecord*>::const_iterator it(lst.begin()); it != lst.end(); ++it)
        buffer += (*it)->write(buffer);
    return buffer;
}

void Tins::DNS::build_suffix_map(uint32_t index, const uint8_t *data, uint32_t sz) {
    uint32_t i(0), suff_sz(data[0]);
    while(i + suff_sz + 1 < sz && suff_sz) {
        i++;
        suffixes.insert(std::make_pair(index + i - 1, string(data + i, data + i + suff_sz)));
        i += suff_sz;
        if(i < sz)
            suff_sz = data[i];
    }
}

uint32_t Tins::DNS::build_suffix_map(uint32_t index, const list<ResourceRecord*> &lst) {
    const string *str;
    for(list<ResourceRecord*>::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        str = (*it)->dname_pointer();
        if(str) {
            build_suffix_map(index, (uint8_t*)str->c_str(), str->size());
            index += str->size() + 1;
        }
        else
            index += sizeof(uint16_t);
        index += sizeof(ResourceRecord::Info);
        uint32_t sz((*it)->data_size());
        if(sz > 4)
           build_suffix_map(index, (*it)->data_pointer(), sz);
        index += sz;
    }
    return index;
}


uint32_t Tins::DNS::build_suffix_map(uint32_t index, const list<Query> &lst) {
    for(list<Query>::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        build_suffix_map(index, (uint8_t*)it->name.c_str(), it->name.size());
        index += it->name.size() + 1 + (sizeof(uint16_t) << 1);
    }
    return index;
}

void Tins::DNS::build_suffix_map() {
    uint32_t index(sizeof(dnshdr));
    index = build_suffix_map(index, queries);
    index = build_suffix_map(index, ans);
    index = build_suffix_map(index, arity);
    build_suffix_map(index, addit);
}

void Tins::DNS::compose_name(const uint8_t *ptr, uint32_t sz, std::string &out) {
    uint32_t i(0);
    while(i < sz) {
        if(i)
            out.push_back('.');
        
        if(ptr[i] & 0xc0) {
            uint16_t index = Utils::net_to_host_s(*((uint16_t*)ptr));
            SuffixMap::iterator it(suffixes.find(index));
            if(it == suffixes.end())
                std::cout << "Could not find " << ptr + i << "\n";
            else
                out += it->second;
            i += 2;
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

void Tins::DNS::convert_resources(const std::list<ResourceRecord*> &lst, std::list<Resource> &res) {
    if(!suffixes.size())
        build_suffix_map();
    const string *str_ptr;
    const uint8_t *ptr;
    uint32_t sz;
    for(list<ResourceRecord*>::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        string dname, addr;
        if((str_ptr = (*it)->dname_pointer()))
            compose_name(reinterpret_cast<const uint8_t*>(str_ptr->c_str()), str_ptr->size(), dname);
        ptr = (*it)->data_pointer();
        sz = (*it)->data_size();
        if(sz == 4)
            addr = Utils::ip_to_string(*(uint32_t*)ptr);
        else 
            compose_name(ptr, sz, addr);
        res.push_back(Resource(dname, addr, (*it)->info.type, (*it)->info.qclass, (*it)->info.ttl));
    }
}

list<Tins::DNS::Query> Tins::DNS::dns_queries() const { 
    list<Query> output;
    for(std::list<Query>::const_iterator it(queries.begin()); it != queries.end(); ++it) {
        string dn;
        unparse_domain_name(it->name, dn);
        output.push_back(Query(dn, it->type, it->qclass));
    }
    return output;
}

list<Tins::DNS::Resource> Tins::DNS::dns_answers() {
    list<Resource> res;
    convert_resources(ans, res);
    return res;
}

