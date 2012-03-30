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

#include <cstring>
#include <iostream> //borrame
#include <cassert>
#include "dns.h"
#include "utils.h"

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
    if(index)
        res = new OffsetedResourceRecord(Utils::net_to_host_s(index));
    else
        res = new NamedResourceRecord(nm);
    res->info.type = Utils::net_to_host_s(type);
    res->info.qclass = Utils::net_to_host_s(qclass);
    res->info.ttl = Utils::net_to_host_l(ttl);
    res->info.dlen = Utils::net_to_host_s(sizeof(uint32_t));
    res->info.data = Utils::net_to_host_l(ip);
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
    NamedResourceRecord *named;
    while(it != lst.end()) {
        named = dynamic_cast<NamedResourceRecord*>(*it);
        if(named && named->name == dname)
            break;
        out += (*it)->size();
        ++it;
    }
    return it != lst.end();
}

void Tins::DNS::parse_domain_name(const std::string &dn, std::string &out) {
    size_t last_index(0), index;
    while((index = dn.find('.', last_index+1)) != string::npos) {
        out.push_back(index - last_index);
        out.append(dn.begin() + last_index, dn.begin() + index);
        last_index = index + 1; //skip dot
    }
    out.push_back(dn.size() - last_index);
    out.append(dn.begin() + last_index, dn.end());
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

uint32_t Tins::DNS::ResourceRecord::write(uint8_t *buffer) const {
    uint32_t sz(do_write(buffer));
    buffer += sz;
    std::memcpy(buffer, &info, sizeof(info));
    return sz + sizeof(info);
}

uint32_t Tins::DNS::OffsetedResourceRecord::do_write(uint8_t *buffer) const {
    std::memcpy(buffer, &offset, sizeof(offset));
    return sizeof(offset);
}

uint32_t Tins::DNS::NamedResourceRecord::do_write(uint8_t *buffer) const {
    std::memcpy(buffer, name.c_str(), name.size() + 1);
    return name.size() + 1;
}
