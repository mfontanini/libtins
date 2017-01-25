/*
 * Copyright (c) 2016, Matias Fontanini
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
#include <sstream>
#include <memory>
#include <cstdio>
#include "dns.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "exceptions.h"
#include "rawpdu.h"
#include "endianness.h"
#include "memory_helpers.h"

using std::string;
using std::copy;
using std::memcpy;
using std::list;
using std::make_pair;

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

PDU::metadata DNS::extract_metadata(const uint8_t* /*buffer*/, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(dns_header))) {
        throw malformed_packet();
    }
    return metadata(total_sz, pdu_flag, PDU::UNKNOWN);
}

DNS::DNS() 
: header_(), answers_idx_(), authority_idx_(), additional_idx_() { 
}

DNS::DNS(const uint8_t* buffer, uint32_t total_sz) 
: answers_idx_(), authority_idx_(), additional_idx_() { 
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    stream.read(records_data_, stream.size());
    // Avoid doing this if there's no data. Otherwise VS's asserts fail.
    if (!records_data_.empty()) {
        InputMemoryStream stream(records_data_);
        uint16_t nquestions = questions_count();
        for (uint16_t i(0); i < nquestions; ++i) {
            skip_to_dname_end(stream);
            stream.skip(sizeof(uint16_t) * 2);
        }
        const uint8_t* base_offset = &records_data_[0];
        answers_idx_ = static_cast<uint32_t>(stream.pointer() - base_offset);
        skip_to_section_end(stream, answers_count());
        authority_idx_ = static_cast<uint32_t>(stream.pointer() - base_offset);
        skip_to_section_end(stream, authority_count());
        additional_idx_ = static_cast<uint32_t>(stream.pointer() - base_offset);
    }
}

void DNS::skip_to_dname_end(InputMemoryStream& stream) const {
    while (stream) {
        uint8_t value = stream.read<uint8_t>();
        if (value == 0) {
            // Found the ending null byte, we're done
            break;
        }
        else {
            if ((value & 0xc0)) {
                // This is an offset label, skip the second byte and we're done
                stream.skip(1);
                break;
            }
            else {
                // This is an actual label, skip its contents
                stream.skip(value);
            }
        }
    }
}

void DNS::skip_to_section_end(InputMemoryStream& stream, 
                              const uint32_t num_records) const {
    for (uint32_t i = 0; i < num_records; ++i) {
        skip_to_dname_end(stream);
        stream.skip(sizeof(uint16_t) * 2 + sizeof(uint32_t));
        uint16_t data_size = stream.read_be<uint16_t>();
        if (!stream.can_read(data_size)) {
            throw malformed_packet();
        }
        stream.skip(data_size);
    }
}

uint32_t DNS::header_size() const {
    return static_cast<uint32_t>(sizeof(header_) + records_data_.size());
}

void DNS::id(uint16_t new_id) {
    header_.id = Endian::host_to_be(new_id);
}

void DNS::type(QRType new_qr) {
    header_.qr = new_qr;
}

void DNS::opcode(uint8_t new_opcode) {
    header_.opcode = new_opcode;
}

void DNS::authoritative_answer(uint8_t new_aa) {
    header_.aa = new_aa;
}

void DNS::truncated(uint8_t new_tc) {
    header_.tc = new_tc;
}

void DNS::recursion_desired(uint8_t new_rd) {
    header_.rd = new_rd;
}

void DNS::recursion_available(uint8_t new_ra) {
    header_.ra = new_ra;
}

void DNS::z(uint8_t new_z) {
    header_.z = new_z;
}

void DNS::authenticated_data(uint8_t new_ad) {
    header_.ad = new_ad;
}

void DNS::checking_disabled(uint8_t new_cd) {
    header_.cd = new_cd;
}

void DNS::rcode(uint8_t new_rcode) {
    header_.rcode = new_rcode;
}

bool DNS::contains_dname(uint16_t type) {
    return type == MX || type == CNAME || type == PTR || type == NS;
}

void DNS::add_query(const query& query) {
    string new_str = encode_domain_name(query.dname());
    size_t previous_length = new_str.size();
    // Epand the string to hold: Type (2 bytes) + Class (2 Bytes)
    new_str.insert(new_str.end(), sizeof(uint16_t) * 2, ' ');
    // Build a stream at the end
    OutputMemoryStream stream(
        (uint8_t*)&new_str[0] + previous_length, 
        sizeof(uint16_t) * 2
    );
    stream.write_be<uint16_t>(query.query_type());
    stream.write_be<uint16_t>(query.query_class());

    uint32_t offset = static_cast<uint32_t>(new_str.size()), threshold = answers_idx_;
    update_records(answers_idx_, answers_count(), threshold, offset);
    update_records(authority_idx_, authority_count(), threshold, offset);
    update_records(additional_idx_, additional_count(), threshold, offset);
    records_data_.insert(
        records_data_.begin() + threshold,
        new_str.begin(),
        new_str.end()
    );
    header_.questions = Endian::host_to_be(static_cast<uint16_t>(questions_count() + 1));
}

void DNS::add_answer(const resource& resource) {
    sections_type sections;
    sections.push_back(make_pair(&authority_idx_, authority_count()));
    sections.push_back(make_pair(&additional_idx_, additional_count()));
    add_record(resource, sections);
    header_.answers = Endian::host_to_be<uint16_t>(
        answers_count() + 1
    );
}

void DNS::add_record(const resource& resource, const sections_type& sections) {
    // We need to check that the data provided is correct. Otherwise, the sections
    // will end up being inconsistent.
    IPv4Address v4_addr;
    IPv6Address v6_addr;
    string buffer = encode_domain_name(resource.dname()), 
           encoded_data;
    // By default the data size is the length of the data field.
    size_t data_size = resource.data().size();
    if (resource.query_type() == A) {
        v4_addr = resource.data();
        data_size = 4;
    }
    else if (resource.query_type() == AAAA) {
        v6_addr = resource.data();
        data_size = IPv6Address::address_size;
    }
    else if (contains_dname(resource.query_type())) { 
        encoded_data = encode_domain_name(resource.data());
        data_size = encoded_data.size();
    }
    size_t offset = buffer.size() + sizeof(uint16_t) * 3 + sizeof(uint32_t) + data_size, 
           threshold = sections.empty() ? records_data_.size() :* sections.front().first;
    // Take into account the MX preference field
    if (resource.query_type() == MX) {
        offset += sizeof(uint16_t);
    }
    for (size_t i = 0; i < sections.size(); ++i) {
        update_records(
            *sections[i].first, 
            sections[i].second, 
            static_cast<uint32_t>(threshold),
            static_cast<uint32_t>(offset)
        );
    }
    
    records_data_.insert(
        records_data_.begin() + threshold,
        offset,
        0
    );
    OutputMemoryStream stream(&records_data_[0] + threshold, offset);
    stream.write(buffer.begin(), buffer.end());
    stream.write_be(resource.query_type());
    stream.write_be(resource.query_class());
    stream.write_be(resource.ttl());
    stream.write_be<uint16_t>(data_size + (resource.query_type() == MX ? 2 : 0));
    if (resource.query_type() == MX) {
        stream.write_be(resource.preference());
    }
    if (resource.query_type() == A) {
        stream.write(v4_addr);
    }
    else if (resource.query_type() == AAAA) {
        stream.write(v6_addr);
    }
    else if (!encoded_data.empty()) {
        stream.write(encoded_data.begin(), encoded_data.end());
    }
    else {
        stream.write(resource.data().begin(), resource.data().end());
    }
}

void DNS::add_authority(const resource& resource) {
    sections_type sections;
    sections.push_back(make_pair(&additional_idx_, additional_count()));
    add_record(resource, sections);
    header_.authority = Endian::host_to_be<uint16_t>(
        authority_count() + 1
    );
}

void DNS::add_additional(const resource& resource){
    add_record(resource, sections_type());
    header_.additional = Endian::host_to_be<uint16_t>(
        additional_count() + 1
    );
}

string DNS::encode_domain_name(const string& dn) {
    string output;
    if (!dn.empty()) {
        size_t last_index(0), index;
        while ((index = dn.find('.', last_index+1)) != string::npos) {
            output.push_back(static_cast<char>(index - last_index));
            output.append(dn.begin() + last_index, dn.begin() + index);
            last_index = index + 1; //skip dot
        }
        output.push_back(static_cast<char>(dn.size() - last_index));
        output.append(dn.begin() + last_index, dn.end());
    }
    output.push_back('\0');
    return output;
}

string DNS::decode_domain_name(const string& domain_name) {
    string output;
    if (domain_name.empty()) {
        return output;
    }
    const uint8_t* ptr = (const uint8_t*)&domain_name[0];
    const uint8_t* end = ptr + domain_name.size();
    while (*ptr) {
        // We can't handle offsets
        if ((*ptr & 0xc0)) {
            throw invalid_domain_name();
        }
        else {
            // It's a label, grab its size.
            uint8_t size = *ptr;
            ptr++;
            if (ptr + size > end) {
                throw malformed_packet();
            }
            // Append a dot if it's not the first one.
            if (!output.empty()) {
                output.push_back('.');
            }
            output.insert(output.end(), ptr, ptr + size);
            ptr += size;
        }
        if (output.size() > 256) {
            throw invalid_domain_name();
        }
    }
    return output;
}

// The output buffer should be at least 256 bytes long. This used to use
// a std::string but it worked about 50% slower, so this is somehow 
// unsafe but a lot faster.
uint32_t DNS::compose_name(const uint8_t* ptr, char* out_ptr) const {
    const uint8_t* start_ptr = ptr;
    const uint8_t* end = &records_data_[0] + records_data_.size();
    const uint8_t* end_ptr = 0;
    char* current_out_ptr = out_ptr;
    while (*ptr) {
        // It's an offset
        if ((*ptr & 0xc0)) {
            if (ptr + sizeof(uint16_t) > end) {
                throw malformed_packet();
            }
            uint16_t index;
            memcpy(&index, ptr, sizeof(uint16_t));
            index = Endian::be_to_host(index) & 0x3fff;
            // Check that the offset is neither too low or too high
            if (index < 0x0c || (&records_data_[0] + (index - 0x0c)) >= end) {
                throw malformed_packet();
            }
            // We've probably found the end of the original domain name. Save it.
            if (end_ptr == 0) {
                end_ptr = ptr + sizeof(uint16_t);
            }
            // Now this is our pointer
            ptr = &records_data_[index - 0x0c];
        }
        else {
            // It's a label, grab its size.
            uint8_t size = *ptr;
            ptr++;
            if (ptr + size > end || current_out_ptr - out_ptr + size + 1 > 255) {
                throw malformed_packet();
            }
            // Append a dot if it's not the first one.
            if (current_out_ptr != out_ptr) {
                *current_out_ptr++ = '.';
            }
            copy(ptr, ptr + size, current_out_ptr);
            current_out_ptr += size;
            ptr += size;
        }
    }
    // Add the null terminator.
    *current_out_ptr = 0;
    if (!end_ptr) {
        end_ptr = ptr + 1;
    }
    return end_ptr - start_ptr;
}

void DNS::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* /*parent*/) {
    OutputMemoryStream stream(buffer, total_sz);
    stream.write(header_);
    stream.write(records_data_.begin(), records_data_.end());
}

// Optimization. Creating an IPv4Address and then using IPv4Address::to_string
// was quite slow. The output buffer should be able to hold an IPv4 address.
void DNS::inline_convert_v4(uint32_t value, char* output) {
    output += sprintf(
        output, 
        "%d.%d.%d.%d", 
        #if TINS_IS_LITTLE_ENDIAN
        value & 0xff, 
        (value >> 8) & 0xff,
        (value >> 16) & 0xff,
        (value >> 24) & 0xff
        #else
        (value >> 24) & 0xff,
        (value >> 16) & 0xff,
        (value >> 8) & 0xff,
        value & 0xff
        #endif // TINS_IS_LITTLE_ENDIAN
    );
    *output = 0;
}

// Parses records in some section.
void DNS::convert_records(const uint8_t* ptr,
                          const uint8_t* end,
                          resources_type& res) const {
    InputMemoryStream stream(ptr, end - ptr);
    char dname[256], small_addr_buf[256];
    while (stream) {
        string data;
        bool used_small_buffer = false;
        // Retrieve the record's domain name.
        stream.skip(compose_name(stream.pointer(), dname));
        // Retrieve the following fields.
        uint16_t type, qclass, data_size, preference = 0;
        uint32_t ttl;
        type = stream.read_be<uint16_t>();
        qclass = stream.read_be<uint16_t>();
        ttl = stream.read_be<uint32_t>();
        data_size = stream.read_be<uint16_t>();
        // Read the preference field if it's MX
        if (type ==  MX) {
            preference = stream.read_be<uint16_t>();
            data_size -= sizeof(uint16_t);
        }
        if (!stream.can_read(data_size)) {
            throw malformed_packet();
        }

        switch (type) {
            case AAAA:
                data = stream.read<IPv6Address>().to_string();
                break;
            case A:
                inline_convert_v4(stream.read<uint32_t>(), small_addr_buf);
                used_small_buffer = true;
                break;
            case NS:
            case CNAME:
            case DNAM:
            case PTR:
            case MX:
                compose_name(stream.pointer(), small_addr_buf);
                stream.skip(data_size);
                used_small_buffer = true;
                break;
            case SOA:
                {
                    stream.skip(compose_name(stream.pointer(), small_addr_buf));
                    data = encode_domain_name(small_addr_buf);
                    stream.skip(compose_name(stream.pointer(), small_addr_buf));
                    data += encode_domain_name(small_addr_buf);
                    const uint32_t size_left = sizeof(uint32_t) * 5;
                    if (!stream.can_read(size_left)) {
                        throw malformed_packet();
                    }
                    data.insert(data.end(), stream.pointer(), stream.pointer() + size_left);
                    stream.skip(size_left);
                }
                break;
            default:
                data.assign(stream.pointer(), stream.pointer() + data_size);
                stream.skip(data_size);
                break;
        }
        res.push_back(
            resource(
                dname, 
                (used_small_buffer) ? small_addr_buf : data, 
                type, 
                qclass, 
                ttl,
                preference
            )
        );
    }
}

// no length checks, records should already be valid
uint8_t* DNS::update_dname(uint8_t* ptr, uint32_t threshold, uint32_t offset) {
    while (*ptr != 0) {
        if ((*ptr & 0xc0)) {
            uint16_t index;
            memcpy(&index, ptr, sizeof(uint16_t));
            index = Endian::be_to_host(index) & 0x3fff;
            if (index > threshold) {
                index = Endian::host_to_be<uint16_t>((index + offset) | 0xc000);
                memcpy(ptr, &index, sizeof(uint16_t));
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
void DNS::update_records(uint32_t& section_start, 
                         uint32_t num_records, 
                         uint32_t threshold, 
                         uint32_t offset) {
    if (section_start < records_data_.size()) {
        uint8_t* ptr = &records_data_[section_start];
        for (uint32_t i = 0; i < num_records; ++i) {
            ptr = update_dname(ptr, threshold, offset);
            uint16_t type;
            memcpy(&type, ptr, sizeof(uint16_t));
            type = Endian::be_to_host(type);
            ptr += sizeof(uint16_t) * 2 + sizeof(uint32_t);
            uint16_t size;
            memcpy(&size, ptr, sizeof(uint16_t));
            size = Endian::be_to_host(size);
            ptr += sizeof(uint16_t);
            if (type == MX) {
                ptr += sizeof(uint16_t);
                size -= sizeof(uint16_t);
            }
            if (contains_dname(type)) {
                update_dname(ptr, threshold, offset);
            }
            ptr += size;
        }
    }
    section_start += offset;
}

DNS::queries_type DNS::queries() const { 
    queries_type output;
    if (!records_data_.empty()) {
        InputMemoryStream stream(&records_data_[0], answers_idx_);
        char buffer[256];
        while (stream) {
            stream.skip(compose_name(stream.pointer(), buffer));
            uint16_t query_type = stream.read_be<uint16_t>();
            uint16_t query_class = stream.read_be<uint16_t>();
            output.push_back(
                query(buffer, (QueryType)query_type, (QueryClass)query_class)
            );
        }
    }
    return output;
}

DNS::resources_type DNS::answers() const {
    resources_type res;
    if (answers_idx_ < records_data_.size()) {
        convert_records(
            &records_data_[0] + answers_idx_, 
            &records_data_[0] + authority_idx_, 
            res
        );
    }
    return res;
}

DNS::resources_type DNS::authority() const {
    resources_type res;
    if (authority_idx_ < records_data_.size()) {
        convert_records(
            &records_data_[0] + authority_idx_, 
            &records_data_[0] + additional_idx_, 
            res
        );
    }
    return res;
}

DNS::resources_type DNS::additional() const {
    resources_type res;
    if (additional_idx_ < records_data_.size()) {
        convert_records(
            &records_data_[0] + additional_idx_, 
            &records_data_[0] + records_data_.size(), 
            res
        );
    }
    return res;
}

bool DNS::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(header_)) {
        return false;
    }
    const dns_header* hdr = (const dns_header*)ptr;
    return hdr->id == header_.id;
}

// SOA record

DNS::soa_record::soa_record() 
: serial_(0), refresh_(0), retry_(0), expire_(0), minimum_ttl_(0) {

}

DNS::soa_record::soa_record(const string& mname,
                            const string& rname,
                            uint32_t serial,
                            uint32_t refresh,
                            uint32_t retry,
                            uint32_t expire,
                            uint32_t minimum_ttl) 
: mname_(mname), rname_(rname), serial_(serial), refresh_(refresh), retry_(retry),
  expire_(expire), minimum_ttl_(minimum_ttl) {

}

DNS::soa_record::soa_record(const uint8_t* buffer, uint32_t total_sz) {
    init(buffer, total_sz);
}

DNS::soa_record::soa_record(const DNS::resource& resource) {
    init((const uint8_t*)&resource.data()[0], resource.data().size());
}

void DNS::soa_record::mname(const string& value) {
    mname_ = value;
}

void DNS::soa_record::rname(const string& value) {
    rname_ = value;
}

void DNS::soa_record::serial(uint32_t value) {
    serial_ = value;
}

void DNS::soa_record::refresh(uint32_t value) {
    refresh_ = value;
}

void DNS::soa_record::retry(uint32_t value) {
    retry_ = value;
}

void DNS::soa_record::expire(uint32_t value) {
    expire_ = value;
}
    
void DNS::soa_record::minimum_ttl(uint32_t value) {
    minimum_ttl_ = value;
}

PDU::serialization_type DNS::soa_record::serialize() const {
    string encoded_mname = DNS::encode_domain_name(mname_);
    string encoded_rname = DNS::encode_domain_name(rname_);
    PDU::serialization_type output(
        encoded_mname.size() + encoded_rname.size() + sizeof(uint32_t) * 5
    );
    OutputMemoryStream stream(output);
    stream.write(encoded_mname.begin(), encoded_mname.end());
    stream.write(encoded_rname.begin(), encoded_rname.end());
    stream.write_be(serial_);
    stream.write_be(refresh_);
    stream.write_be(retry_);
    stream.write_be(expire_);
    stream.write_be(minimum_ttl_);
    return output;
}

void DNS::soa_record::init(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    string domain = (const char*)stream.pointer();
    mname_ = DNS::decode_domain_name(domain);
    stream.skip(domain.size() + 1);
    domain = (const char*)stream.pointer();
    stream.skip(domain.size() + 1);
    rname_ = DNS::decode_domain_name(domain);
    serial_ = stream.read_be<uint32_t>();
    refresh_ = stream.read_be<uint32_t>();
    retry_ = stream.read_be<uint32_t>();
    expire_ = stream.read_be<uint32_t>();
    minimum_ttl_ = stream.read_be<uint32_t>();
}

} // Tins
