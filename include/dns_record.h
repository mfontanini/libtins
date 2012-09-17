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
    struct Info {
        uint16_t type, qclass;
        uint32_t ttl;
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
    Info &info() {
        return info_;
    }
    
    /**
     * \brief Returns a const reference to the info field.
     */
    const Info &info() const {
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

    Info info_;
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
