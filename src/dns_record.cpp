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

#include <cstring>
#include <stdexcept>
#include <typeinfo>
#include "dns_record.h"
#include "endianness.h"

namespace Tins {
bool contains_dname(uint16_t type) {
    type = Endian::be_to_host(type);
    return type == 15 || type == 5 ||
          type == 12 || type == 2;
}
    
DNSResourceRecord::DNSResourceRecord(DNSRRImpl *impl, 
  const uint8_t *d, uint16_t len) : impl(impl)
{
    if(d && len)
        data.assign(d, d + len);
}

DNSResourceRecord::DNSResourceRecord(const uint8_t *buffer, uint32_t size) 
{
    const uint8_t *buffer_end = buffer + size;
    if((*buffer & 0xc0)) {
        uint16_t offset(*reinterpret_cast<const uint16_t*>(buffer));
        offset = Endian::be_to_host(offset) & 0x3fff;
        impl = new OffsetedDNSRRImpl(Endian::host_to_be(offset));
        buffer += sizeof(uint16_t);
    }
    else {
        const uint8_t *str_end(buffer);
        while(str_end < buffer_end && *str_end)
            str_end++;
        if(str_end == buffer_end)
            throw std::runtime_error("Not enough size for a resource domain name.");
        //str_end++;
        impl = new NamedDNSRRImpl(buffer, str_end);
        buffer = ++str_end;
    }
    if(buffer + sizeof(info_) > buffer_end)
        throw std::runtime_error("Not enough size for a resource info.");
    std::memcpy(&info_, buffer, sizeof(info_));
    buffer += sizeof(info_);
    if(buffer + sizeof(uint16_t) > buffer_end)
        throw std::runtime_error("Not enough size for resource data size.");

    // Store the option size.
    data.resize(
        Endian::be_to_host(*reinterpret_cast<const uint16_t*>(buffer))
    );
    buffer += sizeof(uint16_t);
    if(buffer + data.size() > buffer_end)
        throw std::runtime_error("Not enough size for resource data");
    if(contains_dname(info_.type))
        std::copy(buffer, buffer + data.size(), data.begin());
    else if(data.size() == sizeof(uint32_t))
        *(uint32_t*)&data[0] = *(uint32_t*)buffer;
    else
        throw std::runtime_error("Not enough size for resource data");
}

DNSResourceRecord::DNSResourceRecord(const DNSResourceRecord &rhs) 
: info_(rhs.info_), data(rhs.data), impl(rhs.clone_impl()) 
{
    
}

DNSResourceRecord& DNSResourceRecord::operator=(const DNSResourceRecord &rhs) 
{
    delete impl;
    info_ = rhs.info_;
    data = rhs.data;
    impl = rhs.clone_impl();
    return *this;
}

DNSResourceRecord::~DNSResourceRecord() {
    delete impl;
}

uint32_t DNSResourceRecord::write(uint8_t *buffer) const {
    const uint32_t sz(impl ? impl->do_write(buffer) : 0);
    buffer += sz;
    std::memcpy(buffer, &info_, sizeof(info_));
    buffer += sizeof(info_);
    *((uint16_t*)buffer) = Endian::host_to_be<uint16_t>(data.size());
    buffer += sizeof(uint16_t);
    std::copy(data.begin(), data.end(), buffer);
    return sz + sizeof(info_) + sizeof(uint16_t) + data.size();
}

DNSRRImpl *DNSResourceRecord::clone_impl() const {
    return impl ? impl->clone() : 0;
}

bool DNSResourceRecord::has_domain_name() const {
    if(!impl)
        throw std::bad_cast();
    return dynamic_cast<NamedDNSRRImpl*>(impl) != 0;
}

const std::string *DNSResourceRecord::dname() const {
    if(!impl)
        throw std::bad_cast();
    return dynamic_cast<NamedDNSRRImpl&>(*impl).dname_pointer();
}

uint16_t DNSResourceRecord::offset() const {
    return dynamic_cast<OffsetedDNSRRImpl&>(*impl).offset();
}

size_t DNSResourceRecord::impl_size() const {
    return impl ? impl->size() : 0;
}

uint32_t DNSResourceRecord::size() const {
    return sizeof(info_) + data.size() + sizeof(uint16_t) + impl_size(); 
}

bool DNSResourceRecord::matches(const std::string &dname) const {
    return impl ? impl->matches(dname) : false;
}

// OffsetedRecord

OffsetedDNSRRImpl::OffsetedDNSRRImpl(uint16_t off) 
: offset_(off | 0xc0) 
{
    
}

uint32_t OffsetedDNSRRImpl::do_write(uint8_t *buffer) const {
    std::memcpy(buffer, &offset_, sizeof(offset_));
    return sizeof(offset_);
}

uint32_t OffsetedDNSRRImpl::size() const { 
    return sizeof(offset_); 
}

OffsetedDNSRRImpl *OffsetedDNSRRImpl::clone() const {
    return new OffsetedDNSRRImpl(*this);
}

uint16_t OffsetedDNSRRImpl::offset() const {
    return offset_;
}

// NamedRecord

NamedDNSRRImpl::NamedDNSRRImpl(const std::string &nm) 
: name(nm) 
{
    
}

uint32_t NamedDNSRRImpl::size() const { 
    return name.size() + 1; 
}

uint32_t NamedDNSRRImpl::do_write(uint8_t *buffer) const {
    std::copy(name.begin(), name.end() + 1, buffer);
    return name.size() + 1;
}

const std::string *NamedDNSRRImpl::dname_pointer() const {
    return &name;
}

bool NamedDNSRRImpl::matches(const std::string &dname) const { 
    return dname == name; 
}

NamedDNSRRImpl *NamedDNSRRImpl::clone() const {
    return new NamedDNSRRImpl(*this);
}

}
