/*
 * Copyright (c) 2017, Matias Fontanini
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

#ifndef TINS_IPV6_ADDRESS
#define TINS_IPV6_ADDRESS

#include <string>
#include <iosfwd>
#include <functional>
#include <stdint.h>
#include <tins/cxxstd.h>
#include <tins/macros.h>

namespace Tins {

/**
 * Represents an IPv6 address.
 */
class TINS_API IPv6Address {
public:
    static const size_t address_size = 16;
    
    /**
     * The iterator type.
     */
    typedef uint8_t* iterator;
    
    /**
     * The const iterator type.
     */
    typedef const uint8_t* const_iterator;

    /**
     * \brief Constructs an IPv6 address from a prefix length
     *
     * \param prefix_length The length of the prefix
     */
    static IPv6Address from_prefix_length(uint32_t prefix_length);

    /**
     * \brief Default constructor.
     * Initializes this IPv6 address to "::"
     */
    IPv6Address();
    
    /**
     * \brief Constructor from a text representation char*.
     * \param addr The text representation from which to construct this
     * object.
     */
    IPv6Address(const char* addr);
    
    /**
     * \brief Constructor from a text representation std::string.
     * \param addr The text representation from which to construct this
     * object.
     */
    IPv6Address(const std::string& addr);
    
    /**
     * \brief Constructor from a buffer.
     * 
     * The ptr parameter must be at least address_size bytes long.
     * 
     * \param ptr The buffer from which to construct this object.
     */
    IPv6Address(const_iterator ptr);
    
    /**
     * \brief Retrieve the string representation of this address.
     * 
     * \return std::string containing the representation of this address.
     */
    std::string to_string() const;
    
    /**
     * Returns an iterator to the beginning of this address.
     */
    iterator begin() {
        return address_;
    }
    
    /**
     * Returns a const iterator to the beginning of this address.
     */
    const_iterator begin() const {
        return address_;
    }
    
    /**
     * Returns an iterator to the one-past-the-end element of this address.
     */
    iterator end() {
        return address_ + address_size;
    }
    
    /**
     * Returns a const iterator to the one-past-the-end element of this 
     * address.
     */
    const_iterator end() const {
        return address_ + address_size;
    }
    
    /**
     * \brief Compares this address for equality.
     * 
     * \param rhs The address to be compared to.
     * 
     * \return bool indicating whether addresses are equal.
     */
    bool operator==(const IPv6Address& rhs) const {
        return std::equal(begin(), end(), rhs.address_);
    }
    
    /**
     * \brief Compares this address for inequality.
     * 
     * \param rhs The address to be compared to.
     * 
     * \return bool indicating whether addresses are distinct.
     */
    bool operator!=(const IPv6Address& rhs) const {
        return !(*this == rhs);
    }
    
    /**
     * \brief Compares this address for less-than inequality.
     * 
     * \param rhs The address to be compared to.
     * 
     * \return bool indicating whether this address is less-than rhs.
     */
    bool operator<(const IPv6Address& rhs) const {
        return std::lexicographical_compare(begin(), end(), rhs.begin(), rhs.end());
    }
    
    /**
     * \brief Helper function which copies the address into an output
     * iterator.
     * 
     * This is the same as:
     * 
     * std::copy(begin(), end(), iter);
     * 
     * But since some PDUs return a IPv6Address by value, this function
     * can be used to avoid temporaries. 
     * 
     * \param iter The output iterator in which to store this address.
     * \return OutputIterator pointing to one-past the last position
     * written.
     */
    template<typename OutputIterator>
    OutputIterator copy(OutputIterator iter) const {
        return std::copy(begin(), end(), iter);
    }
    
    /**
     * \brief Returns true if this is a loopback IPv6 address.
     * 
     * This method returns true if this address is the ::1/128 address,
     * false otherwise.
     */
    bool is_loopback() const;

    /**
     * \brief Returns true if this is a multicast IPv6 address.
     * 
     * This method returns true if this address is in the address range
     * ff00::/8, false otherwise.
     */
    bool is_multicast() const;

    /**
     * \brief Returns the size of an IPv6 Address.
     *
     * This returns the value of IPv6Address::address_size
     */
    size_t size() const {
        return address_size;
    }
    
    /**
     * \brief Writes this address in hex-notation to a std::ostream.
     * 
     * \param os The stream in which to write the address.
     * \param addr The parameter to be written.
     * \return std::ostream& pointing to the os parameter.
     */
    TINS_API friend std::ostream& operator<<(std::ostream& os, const IPv6Address& addr);

    /**
     * Applies a mask to an address
     */
    TINS_API friend IPv6Address operator&(const IPv6Address& lhs, const IPv6Address& rhs);

private:
    void init(const char* addr);

    uint8_t address_[address_size];
};

} // Tins

#if TINS_IS_CXX11
namespace std {

template<>
struct hash<Tins::IPv6Address> {
    // Implementation taken from boost.functional
    size_t operator()(const Tins::IPv6Address& addr) const {
        std::size_t output = Tins::IPv6Address::address_size;
        Tins::IPv6Address::const_iterator iter = addr.begin();
        for (; iter != addr.end(); ++iter) {
            output ^= *iter + 0x9e3779b9 + (output << 6) + (output >> 2);
        }
        return output;
    }
};

} // std

#endif // TINS_IS_CXX11

#endif // TINS_IPV6_ADDRESS
