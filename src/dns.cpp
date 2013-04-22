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

#include <utility>
#include <stdexcept>
#include <cassert>
#include <sstream>
#include <memory>
#include "dns.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "exceptions.h"
#include "rawpdu.h"

using std::string;
using std::list;

namespace Tins {

DNS::DNS() : extra_size(0) {
    std::memset(&dns, 0, sizeof(dns));
}

DNS::DNS(const uint8_t *buffer, uint32_t total_sz) : extra_size(0) {
    if(total_sz < sizeof(dnshdr))
        throw malformed_packet();
    std::memcpy(&dns, buffer, sizeof(dnshdr));
    const uint8_t *end(buffer + total_sz);
    uint16_t nquestions(questions_count());
    buffer += sizeof(dnshdr);
    total_sz -= sizeof(dnshdr);
    for(uint16_t i(0); i < nquestions; ++i) {
        const uint8_t *ptr(buffer);
        while(ptr < end && *ptr)
            ptr++;
        Query query;
        if((ptr + (sizeof(uint16_t) * 2)) >= end)
            throw malformed_packet();
        query.dname(string(buffer, ptr));
        ptr++;
        const uint16_t *opt_ptr = reinterpret_cast<const uint16_t*>(ptr);
        query.type((QueryType)*(opt_ptr++));
        query.query_class((QueryClass)*(opt_ptr++));
        queries_.push_back(query);
        total_sz -= reinterpret_cast<const uint8_t*>(opt_ptr) - buffer;
        extra_size += reinterpret_cast<const uint8_t*>(opt_ptr) - buffer;
        buffer = reinterpret_cast<const uint8_t*>(opt_ptr);
    }
    buffer = build_resource_list(ans, buffer, total_sz, answers_count());
    buffer = build_resource_list(arity, buffer, total_sz, authority_count());
    build_resource_list(addit, buffer, total_sz, additional_count());
    if(total_sz)
        inner_pdu(new RawPDU(buffer, total_sz));
}

const uint8_t *DNS::build_resource_list(ResourcesType &lst, const uint8_t *ptr, uint32_t &sz, uint16_t nrecs) {
    const uint8_t *ptr_end(ptr + sz);
    const uint8_t *parse_start(ptr);
    for(uint16_t i(0); i < nrecs; ++i) {
        const uint8_t *this_opt_start(ptr);
        if(ptr + sizeof(uint16_t) > ptr_end)
            throw malformed_packet();
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

void DNS::add_query(const Query &query) {
    string new_str;
    parse_domain_name(query.dname(), new_str);
    
    queries_.push_back(
        Query(
            new_str, 
            (QueryType)Endian::host_to_be<uint16_t>(query.type()), 
            (QueryClass)Endian::host_to_be<uint16_t>(query.query_class())
        )
    );
    extra_size += new_str.size() + 1 + (sizeof(uint16_t) << 1);
    dns.questions = Endian::host_to_be<uint16_t>(queries_.size());
}

void DNS::add_answer(const string &name, const DNSResourceRecord::info &info, 
  address_type ip) 
{
    ans.push_back(make_record(name, info, Endian::host_to_be((uint32_t)ip)));
    dns.answers = Endian::host_to_be<uint16_t>(ans.size());
}

void DNS::add_answer(const string &name, const DNSResourceRecord::info &info, 
  address_v6_type ip) 
{
    ans.push_back(make_record(name, info, ip.begin(), address_v6_type::address_size));
    dns.answers = Endian::host_to_be<uint16_t>(ans.size());
}

void DNS::add_answer(const std::string &name, const DNSResourceRecord::info &info, 
  const std::string &dname) 
{
    string new_str;
    parse_domain_name(dname, new_str);
    DNSResourceRecord res = make_record(name, info, new_str);
    ans.push_back(res);
    dns.answers = Endian::host_to_be<uint16_t>(ans.size());
}

void DNS::add_answer(const std::string &name, const DNSResourceRecord::info &info, 
  const uint8_t *data, uint32_t sz) 
{
    ans.push_back(make_record(name, info, data, sz));
    dns.answers = Endian::host_to_be<uint16_t>(ans.size());
}

void DNS::add_authority(const string &name, const DNSResourceRecord::info &info, 
  const uint8_t *data, uint32_t sz) 
{
    arity.push_back(make_record(name, info, data, sz));
    dns.authority = Endian::host_to_be<uint16_t>(arity.size());
}

void DNS::add_additional(const string &name, const DNSResourceRecord::info &info, 
uint32_t ip) 
{
    addit.push_back(make_record(name, info, ip));
    dns.additional = Endian::host_to_be<uint16_t>(addit.size());
}

DNSResourceRecord DNS::make_record(const std::string &name, const DNSResourceRecord::info &info, uint32_t ip) {
    ip = Endian::host_to_be(ip);
    return make_record(name, info, reinterpret_cast<uint8_t*>(&ip), sizeof(ip));
}

DNSResourceRecord DNS::make_record(const std::string &name, 
  const DNSResourceRecord::info &info, const std::string &dname) 
{
    return make_record(name, info, reinterpret_cast<const uint8_t*>(dname.c_str()), dname.size() + 1);
}

DNSResourceRecord DNS::make_record(const std::string &name, 
  const DNSResourceRecord::info &info, const uint8_t *ptr, uint32_t len) 
{
    string nm;
    parse_domain_name(name, nm);
    uint16_t index = find_domain_name(nm);
    DNSResourceRecord res;
    if(index)
        res = make_offseted_record(Endian::host_to_be(index), ptr, len);
    else
        res = make_named_record(nm, ptr, len);
    res.information().type = Endian::host_to_be<uint16_t>(info.type);
    res.information().qclass = Endian::host_to_be<uint16_t>(info.qclass);
    res.information().ttl = Endian::host_to_be(info.ttl);
    extra_size += res.size();
    return res;
}

uint32_t DNS::find_domain_name(const std::string &dname) {
    uint16_t index(sizeof(dnshdr));
    list<Query>::const_iterator it(queries_.begin());
    for(; it != queries_.end() && it->dname() != dname; ++it)
        index += it->dname().size() + 1 + (sizeof(uint16_t) << 1);
    if(it != queries_.end() ||
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
    #ifdef TINS_DEBUG
    assert(total_sz >= sizeof(dns) + extra_size);
    #endif
    std::memcpy(buffer, &dns, sizeof(dns)); 
    buffer += sizeof(dns);
    for(list<Query>::const_iterator it(queries_.begin()); it != queries_.end(); ++it) {
        std::copy(it->dname().begin(), it->dname().end(), buffer);
        buffer += it->dname().size();
        *buffer++ = 0;
        *((uint16_t*)buffer) = it->type();
        buffer += sizeof(uint16_t);
        *((uint16_t*)buffer) = it->query_class();
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

void DNS::add_suffix(uint32_t index, const uint8_t *data, uint32_t sz) const {
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

uint32_t DNS::build_suffix_map(uint32_t index, const ResourcesType &lst) const {
    const string *str;
    for(ResourcesType::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        str = it->has_domain_name() ? it->dname() : 0;
        if(str) {
            add_suffix(index, (uint8_t*)str->c_str(), str->size());
            index += str->size() + 1;
        }
        else
            index += sizeof(uint16_t);
        index += sizeof(DNSResourceRecord::info) + sizeof(uint16_t);
        uint32_t sz(it->data_size());
        const uint8_t *ptr = it->data_ptr();
        if(Endian::be_to_host(it->information().type) == MX) {
            ptr += 2;
            sz -= 2;
            index += 2;
        }
        if(contains_dname(it->information().type))
            add_suffix(index, ptr, sz);
        index += sz;
    }
    return index;
}

uint32_t DNS::build_suffix_map(uint32_t index, const list<Query> &lst) const {
    for(list<Query>::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        add_suffix(index, (uint8_t*)it->dname().c_str(), it->dname().size());
        index += it->dname().size() + 1 + (sizeof(uint16_t) << 1);
    }
    return index;
}

void DNS::build_suffix_map() const {
    uint32_t index(sizeof(dnshdr));
    index = build_suffix_map(index, queries_);
    index = build_suffix_map(index, ans);
    index = build_suffix_map(index, arity);
    build_suffix_map(index, addit);
}

void DNS::compose_name(const uint8_t *ptr, uint32_t sz, std::string &out) const {
    uint32_t i(0);
    while(i < sz) {
        if(i && ptr[i])
            out.push_back('.');
        if((ptr[i] & 0xc0)) {
            uint16_t index = Endian::be_to_host(*((uint16_t*)(ptr + i)));
            index &= 0x3fff;
            SuffixMap::iterator it(suffixes.find(index));
            SuffixIndices::iterator suff_it(suffix_indices.find(index));
            // We need at least a suffix or a suffix index to compose 
            // the domain name
            if(it == suffixes.end() && suff_it == suffix_indices.end())
                throw malformed_packet();
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

void DNS::convert_resources(const ResourcesType &lst, std::list<Resource> &res) const {
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
            if(Endian::be_to_host(it->information().type) ==  MX) {
                ptr += 2;
                sz -= 2;
            }
            if(Endian::be_to_host(it->information().type) == DNS::AAAA) {
                if(sz != 16)
                    throw std::runtime_error("Malformed IPv6 address");
                addr = IPv6Address(ptr).to_string();
            }
            else
                compose_name(ptr, sz, addr);
        }
        res.push_back(
            Resource(dname, addr, Endian::be_to_host(it->information().type), 
              Endian::host_to_be(it->information().qclass), 
              Endian::be_to_host(it->information().ttl)
            )
        );
    }
}

DNS::queries_type DNS::queries() const { 
    queries_type output;
    for(std::list<Query>::const_iterator it(queries_.begin()); it != queries_.end(); ++it) {
        string dn;
        unparse_domain_name(it->dname(), dn);
        output.push_back(
            Query(
                dn, 
                (QueryType)Endian::be_to_host<uint16_t>(it->type()), 
                (QueryClass)Endian::be_to_host<uint16_t>(it->query_class())
            )
        );
    }
    return output;
}

DNS::resources_type DNS::answers() const {
    resources_type res;
    convert_resources(ans, res);
    return res;
}

bool DNS::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(total_sz < sizeof(dnshdr))
        return false;
    const dnshdr *hdr = (const dnshdr*)ptr;
    return hdr->id == dns.id;
}
}
