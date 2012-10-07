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

#ifndef TINS_DNS_RECORD_H
#define TINS_DNS_RECORD_H

#include <string>
#include <vector>
#include <stdint.h>

namespace Tins {
class DNSRRImpl;

/**
 * \brief Abstracts a DNS resource record.
 */
class DNSResourceRecord {
public:
    /**
     * \brief The type used to store resource records' information.
     */
    struct info {
        uint16_t type, qclass;
        uint32_t ttl;
        
        info(uint16_t tp, uint16_t qc, uint32_t tm) 
          : type(tp), qclass(qc), ttl(tm) { }
        
        info() : type(), qclass(), ttl() {}
    } __attribute__((packed));
    
    /**
     * \brief Constructs a record.
     * \param impl A pointer to the impl object.
     * \param data A pointer to the start of the data buffer.
     * \param len The length of the data.
     */
    DNSResourceRecord(DNSRRImpl *impl = 0, const uint8_t *data = 0, uint16_t len = 0);
    
    /**
     * \brief Constructs a record.
     * \param buffer A pointer to the start of the data buffer.
     * \param len The length of the data.
     */
    DNSResourceRecord(const uint8_t *buffer, uint32_t size);
    
    /**
     * \brief Constructs a record from an input range.
     * \param impl A pointer to the impl object.
     * \param start The begining of the range.
     * \param end The end of the range.
     */
    template<typename ForwardIterator>
    DNSResourceRecord(DNSRRImpl *impl, ForwardIterator start, ForwardIterator end) 
    : impl(impl), data(start, end)
    {  }
    
    /**
     * \brief Copy constructor.
     * 
     * This handles cloning the impl object.
     * \param rhs The record which will be copied.
     */
    DNSResourceRecord(const DNSResourceRecord &rhs);
    
    /**
     * \brief Copy assignment operator.
     * 
     * This handles cloning the impl object.
     * \param rhs The record which will be copied.
     */
    DNSResourceRecord& operator=(const DNSResourceRecord &rhs);
    
    /**
     * \brief Destructor.
     * 
     * This frees the impl object.
     */
    ~DNSResourceRecord();

    /**
     * \brief Writes this record to a buffer.
     * 
     * \param buffer The buffer in which to store the serialization.
     * \return uint32_t containing the number of bytes written.
     */
    uint32_t write(uint8_t *buffer) const;
    
    /**
     * \brief Returns the size of the data in this record.
     */
    uint32_t data_size() const {
        return data.size();
    }
    
    /**
     * \brief Returns the pointer to the start of the data buffer.
     */
    const uint8_t *data_ptr() const {
        return &data[0];
    }
    
    /**
     * \brief Returns a bool indicating whether this record contains
     * a domain name as the name being resolved.
     */
    bool has_domain_name() const;
    
    /**
     * \brief Returns a pointer to the domain name stored in this record.
     * 
     * This will throw a std::bad_cast exception if the impl object is
     * not of the type NamedDNSRRImpl.
     */
    const std::string *dname() const;
    
    /**
     * \brief Returns the offset stored in this record.
     * 
     * This will throw a std::bad_cast exception if the impl object is
     * not of the type OffsetedDNSRRImpl.
     */
    uint16_t offset() const;
    
    /**
     * \brief Returns the size of this record.
     */
    uint32_t size() const;
    
    /**
     * \brief Returns a reference to the info field.
     */
    info &information() {
        return info_;
    }
    
    /**
     * \brief Returns a const reference to the info field.
     */
    const info &information() const {
        return info_;
    }
    
    /**
     * \brief Checks if the domain name stored in this record matches
     * the given one.
     * 
     * This is a shortcut 
     */
    bool matches(const std::string &dname) const;
private:
    DNSRRImpl *clone_impl() const;
    size_t impl_size() const;

    info info_;
    std::vector<uint8_t> data;
    DNSRRImpl *impl;
};

/** 
 * \cond
 */
class DNSRRImpl {
public:
    virtual ~DNSRRImpl() {}
    virtual uint32_t size() const = 0;
    virtual uint32_t do_write(uint8_t *buffer) const = 0;
    virtual bool matches(const std::string &dname) const { return false; }
    virtual DNSRRImpl *clone() const = 0;
};

class OffsetedDNSRRImpl : public DNSRRImpl {
public:
    OffsetedDNSRRImpl(uint16_t off);
    
    uint32_t do_write(uint8_t *buffer) const;
    uint32_t size() const;
    OffsetedDNSRRImpl *clone() const;
    uint16_t offset() const;
private:
    uint16_t offset_;
};

class NamedDNSRRImpl : public DNSRRImpl {
public:
    NamedDNSRRImpl(const std::string &nm);
    
    template<typename ForwardIterator>
    NamedDNSRRImpl(ForwardIterator start, ForwardIterator end)
    : name(start, end) 
    { }
    
    uint32_t do_write(uint8_t *buffer) const;
    
    uint32_t size() const;
    
    bool matches(const std::string &dname) const;
    
    const std::string *dname_pointer() const;
    NamedDNSRRImpl *clone() const;
private:
    std::string name;
};

/** 
 * \endcond
 */

inline DNSResourceRecord make_offseted_record(uint16_t offset, const uint8_t *data = 0, uint32_t size = 0) {
    return DNSResourceRecord(new OffsetedDNSRRImpl(offset), data, size);
}

inline DNSResourceRecord make_named_record(const std::string &name, const uint8_t *data = 0, uint32_t size = 0) {
    return DNSResourceRecord(new NamedDNSRRImpl(name), data, size);
}
}

#endif // TINS_DNS_RECORD_H
