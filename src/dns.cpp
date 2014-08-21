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

#include <utility>
#include <stdexcept>
#include <cassert>
#include <sstream>
#include <memory>
#include <cstdio>
#include "dns.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "exceptions.h"
#include "rawpdu.h"

using std::string;
using std::list;

namespace Tins {

DNS::DNS() 
: answers_idx(), authority_idx(), additional_idx()
{ 
    std::memset(&dns, 0, sizeof(dns));
}

DNS::DNS(const uint8_t *buffer, uint32_t total_sz) 
: answers_idx(), authority_idx(), additional_idx()
{ 
    if(total_sz < sizeof(dnshdr))
        throw malformed_packet();
    std::memcpy(&dns, buffer, sizeof(dnshdr));
    records_data.assign(
        buffer + sizeof(dnshdr),
        buffer + total_sz
    );
    buffer = &records_data[0];
    const uint8_t *end = &records_data[0] + records_data.size(), *prev_start = buffer;
    uint16_t nquestions = questions_count();
    for(uint16_t i(0); i < nquestions; ++i) {
        buffer = find_dname_end(buffer);
        if((buffer + (sizeof(uint16_t) * 2)) > end)
            throw malformed_packet();
        buffer += sizeof(uint16_t) * 2;
    }
    answers_idx = buffer - prev_start;
    authority_idx = find_section_end(&records_data[answers_idx], answers_count()) - &records_data[0];
    additional_idx = find_section_end(&records_data[authority_idx], authority_count()) - &records_data[0];
}

const uint8_t* DNS::find_dname_end(const uint8_t *ptr) const {
    const uint8_t *end = &records_data[0] + records_data.size();
    while(ptr < end) {
        if(*ptr == 0) {
            ++ptr;
            break;
        }
        else {
            if((*ptr & 0xc0)) {
                ptr += sizeof(uint16_t);
                break;
            }
            else {
                uint8_t size = *ptr;
                ptr += size + 1;
            }
        }
    }
    return ptr;
}

const uint8_t *DNS::find_section_end(const uint8_t *ptr, const uint32_t num_records) const {
    const uint8_t *end = &records_data[0] + records_data.size();
    uint16_t uint16_t_buffer;
    for(uint32_t i = 0; i < num_records; ++i) {
        ptr = find_dname_end(ptr);
        if(ptr + sizeof(uint16_t) * 3 + sizeof(uint32_t) > end)
            throw malformed_packet();
        ptr += sizeof(uint16_t) * 2 + sizeof(uint32_t);
        std::memcpy(&uint16_t_buffer, ptr, sizeof(uint16_t));
        uint16_t data_size = Endian::be_to_host(uint16_t_buffer); // Data size
        ptr += sizeof(uint16_t);
        if(ptr + data_size > end)
            throw malformed_packet();
        ptr += data_size;
    }
    return ptr;
}

uint32_t DNS::header_size() const {
    return sizeof(dns) + records_data.size();
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
    return type == MX || type == CNAME ||
          type == PTR || type == NS;
}

void DNS::add_query(const Query &query) {
    string new_str = encode_domain_name(query.dname());
    // Type (2 bytes) + Class (2 Bytes)
    new_str.insert(new_str.end(), sizeof(uint16_t) * 2, ' ');
    uint16_t uint16_t_buffer;
    uint16_t_buffer = Endian::host_to_be<uint16_t>(query.type());
    std::memcpy(&new_str[new_str.size() - 4], &uint16_t_buffer, sizeof(uint16_t));
    uint16_t_buffer = Endian::host_to_be<uint16_t>(query.query_class());
    std::memcpy(&new_str[new_str.size() - 2], &uint16_t_buffer, sizeof(uint16_t));

    uint32_t offset = new_str.size(), threshold = answers_idx;
    update_records(answers_idx, answers_count(), threshold, offset);
    update_records(authority_idx, authority_count(), threshold, offset);
    update_records(additional_idx, additional_count(), threshold, offset);
    records_data.insert(
        records_data.begin() + threshold,
        new_str.begin(),
        new_str.end()
    );
    dns.questions = Endian::host_to_be<uint16_t>(
        questions_count() + 1
    );
}

void DNS::add_answer(const Resource &resource) {
    sections_type sections;
    sections.push_back(std::make_pair(&authority_idx, authority_count()));
    sections.push_back(std::make_pair(&additional_idx, additional_count()));
    add_record(resource, sections);
    dns.answers = Endian::host_to_be<uint16_t>(
        answers_count() + 1
    );
}

void DNS::add_record(const Resource &resource, const sections_type &sections) {
    // We need to check that the data provided is correct. Otherwise, the sections
    // will end up being inconsistent.
    IPv4Address v4_addr;
    IPv6Address v6_addr;
    std::string buffer = encode_domain_name(resource.dname()), encoded_data;
    // By default the data size is the length of the data field.
    uint32_t data_size = resource.data().size();
    if(resource.type() == A) {
        v4_addr = resource.data();
        data_size = 4;
    }
    else if(resource.type() == AAAA) {
        v6_addr = resource.data();
        data_size = IPv6Address::address_size;
    }
    else if(contains_dname(resource.type())) { 
        encoded_data = encode_domain_name(resource.data());
        data_size = encoded_data.size();
    }
    uint32_t offset = buffer.size() + sizeof(uint16_t) * 3 + sizeof(uint32_t) + data_size, 
            threshold = sections.empty() ? records_data.size() : *sections.front().first;
    // Skip the preference field
    if(resource.type() == MX) {
        offset += sizeof(uint16_t);
    }
    for(size_t i = 0; i < sections.size(); ++i) {
        update_records(*sections[i].first, sections[i].second, threshold, offset);
    }
    
    records_data.insert(
        records_data.begin() + threshold,
        offset,
        0
    );
    uint8_t *ptr = std::copy(
        buffer.begin(),
        buffer.end(),
        &records_data[threshold]
    );

    uint16_t uint16_t_buffer;
    uint32_t uint32_t_buffer;

    uint16_t_buffer = Endian::host_to_be(resource.type());
    std::memcpy(ptr, &uint16_t_buffer, sizeof(uint16_t));
    ptr += sizeof(uint16_t);
    uint16_t_buffer = Endian::host_to_be(resource.query_class());
    std::memcpy(ptr, &uint16_t_buffer, sizeof(uint16_t));
    ptr += sizeof(uint16_t);
    uint32_t_buffer = Endian::host_to_be(resource.ttl());
    std::memcpy(ptr, &uint32_t_buffer, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    uint16_t_buffer = Endian::host_to_be<uint16_t>(
        data_size + (resource.type() == MX ? 2 : 0)
    );
    std::memcpy(ptr, &uint16_t_buffer, sizeof(uint16_t));
    ptr += sizeof(uint16_t);
    if(resource.type() == MX) {
        ptr += sizeof(uint16_t);
    }
    if(resource.type() == A) {
        uint32_t ip_int = v4_addr;
        std::memcpy(ptr, &ip_int, sizeof(ip_int));
    }
    else if(resource.type() == AAAA) {
        std::copy(v6_addr.begin(), v6_addr.end(), ptr);
    }
    else if(!encoded_data.empty()) {
        std::copy(encoded_data.begin(), encoded_data.end(), ptr);
    }
    else {
        std::copy(resource.data().begin(), resource.data().end(), ptr);
    }
}

void DNS::add_authority(const Resource &resource) {
    sections_type sections;
    sections.push_back(std::make_pair(&additional_idx, additional_count()));
    add_record(resource, sections);
    dns.authority = Endian::host_to_be<uint16_t>(
        authority_count() + 1
    );
}

void DNS::add_additional(const Resource &resource){
    add_record(resource, sections_type());
    dns.additional = Endian::host_to_be<uint16_t>(
        additional_count() + 1
    );
}

std::string DNS::encode_domain_name(const std::string &dn) {
    std::string output;
    size_t last_index(0), index;
    if(!dn.empty()) {
        while((index = dn.find('.', last_index+1)) != string::npos) {
            output.push_back(index - last_index);
            output.append(dn.begin() + last_index, dn.begin() + index);
            last_index = index + 1; //skip dot
        }
        output.push_back(dn.size() - last_index);
        output.append(dn.begin() + last_index, dn.end());
    }
    output.push_back('\0');
    return output;
}

// The output buffer should be at least 256 bytes long. This used to use
// a std::string but it worked about 50% slower, so this is somehow 
// unsafe but a lot faster.
const uint8_t* DNS::compose_name(const uint8_t *ptr, char *out_ptr) const {
    const uint8_t *end = &records_data[0] + records_data.size();
    const uint8_t *end_ptr = 0;
    char *current_out_ptr = out_ptr;
    while(*ptr) {
        // It's an offset
        if((*ptr & 0xc0)) {
            if(ptr + sizeof(uint16_t) > end)
                throw malformed_packet();
            uint16_t index;
            std::memcpy(&index, ptr, sizeof(uint16_t));
            index = Endian::be_to_host(index) & 0x3fff;
            // Check that the offset is neither too low or too high
            if(index < 0x0c || &records_data[index - 0x0c] >= ptr)
                throw malformed_packet();
            // We've probably found the end of the original domain name. Save it.
            if(end_ptr == 0)
                end_ptr = ptr + sizeof(uint16_t);
            // Now this is our pointer
            ptr = &records_data[index - 0x0c];
        }
        else {
            // It's a label, grab its size.
            uint8_t size = *ptr;
            ptr++;
            if(ptr + size > end || current_out_ptr - out_ptr + size + 1 > 255)
                throw malformed_packet();
            // Append a dot if it's not the first one.
            if(current_out_ptr != out_ptr)
                *current_out_ptr++ = '.';
            std::copy(
                ptr,
                ptr + size,
                current_out_ptr
            );
            current_out_ptr += size;
            ptr += size;
        }
    }
    // Add the null terminator.
    *current_out_ptr = 0;
    return end_ptr ? end_ptr : (ptr + 1);
}

void DNS::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    #ifdef TINS_DEBUG
    assert(total_sz >= sizeof(dns) + records_data.size());//extra_size);
    #endif
    std::memcpy(buffer, &dns, sizeof(dns)); 
    buffer += sizeof(dns);
    std::copy(records_data.begin(), records_data.end(), buffer);
}

// Optimization. Creating an IPv4Address and then using IPv4Address::to_string
// was quite slow. The output buffer should be able to hold an IPv4 address.
void DNS::inline_convert_v4(uint32_t value, char *output) {
    output += sprintf(
        output, 
        "%d.%d.%d.%d", 
        value & 0xff, 
        (value >> 8) & 0xff,
        (value >> 16) & 0xff,
        (value >> 24) & 0xff
    );
    *output = 0;
}

// Parses records in some section.
void DNS::convert_records(const uint8_t *ptr, const uint8_t *end, resources_type &res) const {
    char dname[256], small_addr_buf[256];
    while(ptr < end) {
        std::string addr;
        bool used_small_buffer = false;
        // Retrieve the record's domain name.
        ptr = compose_name(ptr, dname);
        // 3 uint16_t fields: Type + Class + Data size
        // 1 uint32_t field: TTL
        if(ptr + sizeof(uint16_t) * 3 + sizeof(uint32_t) > end)
            throw malformed_packet();
        // Retrieve the following fields.
        uint16_t type, qclass, data_size;
        uint32_t ttl;
        std::memcpy(&type, ptr, sizeof(uint16_t)); // Type
        type = Endian::be_to_host(type);
        ptr += sizeof(uint16_t);
        std::memcpy(&qclass, ptr, sizeof(uint16_t)); // Class
        qclass = Endian::be_to_host(qclass);
        ptr += sizeof(uint16_t);
        std::memcpy(&ttl, ptr, sizeof(uint32_t)); // TTL
        ttl = Endian::be_to_host(ttl);
        ptr += sizeof(uint32_t);
        std::memcpy(&data_size, ptr, sizeof(uint16_t)); // Data size
        data_size = Endian::be_to_host(data_size);
        ptr += sizeof(uint16_t);
        // Skip the preference field if it's MX
        if(type ==  MX) {
            if(data_size < 2)
                throw malformed_packet();
            ptr += 2;
            data_size -= 2;
        }
        if(ptr + data_size > end)
            throw malformed_packet();

        switch(type) {
            case AAAA:
                if(data_size != 16)
                    throw malformed_packet();
                addr = IPv6Address(ptr).to_string();
                break;
            case A:
                if(data_size == 4) {
                    uint32_t uint32_t_buffer;
                    std::memcpy(&uint32_t_buffer, ptr, sizeof(uint32_t));
                    inline_convert_v4(uint32_t_buffer, small_addr_buf);
                    used_small_buffer = true;
                }
                else
                    throw malformed_packet();
                break;
            case NS:
            case CNAME:
            case DNAM:
            case PTR:
            case MX:
                compose_name(ptr, small_addr_buf);
                used_small_buffer = true;
                break;
            default:
                if(data_size < sizeof(small_addr_buf) - 1) {
                    std::copy(
                        ptr,
                        ptr + data_size,
                        small_addr_buf
                    );
                    // null terminator
                    small_addr_buf[data_size] = 0;
                    used_small_buffer = true;
                }
                else
                    addr.assign(ptr, ptr + data_size);
                break;
        }
        ptr += data_size;
        res.push_back(
            Resource(
                dname, 
                (used_small_buffer) ? small_addr_buf : addr, 
                type, 
                qclass, 
                ttl
            )
        );
    }
}

// no length checks, records should already be valid
uint8_t *DNS::update_dname(uint8_t *ptr, uint32_t threshold, uint32_t offset) {
    while(*ptr != 0) {
        if((*ptr & 0xc0)) {
            uint16_t index;
            std::memcpy(&index, ptr, sizeof(uint16_t));
            index = Endian::be_to_host(index) & 0x3fff;
            if(index > threshold) {
                index = Endian::host_to_be<uint16_t>((index + offset) | 0xc000);
                std::memcpy(ptr, &index, sizeof(uint16_t));
            }
            ptr += sizeof(uint16_t);
            break;
        }
        else {
            ptr += *ptr + 1;
        }
    }
    return ptr;
}

// Updates offsets in domain names inside records.
// No length checks, records are already valid.
void DNS::update_records(uint32_t &section_start, uint32_t num_records, uint32_t threshold, uint32_t offset) {
    uint8_t *ptr = &records_data[section_start];
    for(uint32_t i = 0; i < num_records; ++i) {
        ptr = update_dname(ptr, threshold, offset);
        uint16_t type;
        std::memcpy(&type, ptr, sizeof(uint16_t));
        type = Endian::be_to_host(type);
        ptr += sizeof(uint16_t) * 2 + sizeof(uint32_t);
        uint16_t size;
        std::memcpy(&size, ptr, sizeof(uint16_t));
        size = Endian::be_to_host(size);
        ptr += sizeof(uint16_t);
        if(type == MX) {
            ptr += sizeof(uint16_t);
            size -= sizeof(uint16_t);
        }
        if(contains_dname(type)) {
            update_dname(ptr, threshold, offset);
        }
        ptr += size;
    }
    section_start += offset;
}

DNS::queries_type DNS::queries() const { 
    queries_type output;
    const uint8_t *ptr = &records_data[0], *end = &records_data[answers_idx];
    char buffer[256];
    uint16_t tmp_query_type;
    uint16_t tmp_query_class;
    while(ptr < end) {
        ptr = compose_name(ptr, buffer);
        if(ptr + sizeof(uint16_t) * 2 > end) 
            throw malformed_packet();
        std::memcpy(&tmp_query_type, ptr, sizeof(uint16_t));
        std::memcpy(&tmp_query_class, ptr + 2, sizeof(uint16_t));
        output.push_back(
            Query(
                buffer, 
                (QueryType)Endian::be_to_host(tmp_query_type), 
                (QueryClass)Endian::be_to_host(tmp_query_class)
            )
        );
        ptr += sizeof(uint16_t) * 2;
    }
    return output;
}

DNS::resources_type DNS::answers() const {
    resources_type res;
    convert_records(
        &records_data[answers_idx], 
        &records_data[authority_idx], 
        res
    );
    return res;
}

DNS::resources_type DNS::authority() const {
    resources_type res;
    convert_records(
        &records_data[authority_idx], 
        &records_data[additional_idx], 
        res
    );
    return res;
}

DNS::resources_type DNS::additional() const {
    resources_type res;
    convert_records(
        &records_data[additional_idx], 
        &records_data[records_data.size()], 
        res
    );
    return res;
}

bool DNS::matches_response(const uint8_t *ptr, uint32_t total_sz) const {
    if(total_sz < sizeof(dnshdr))
        return false;
    const dnshdr *hdr = (const dnshdr*)ptr;
    return hdr->id == dns.id;
}
}
