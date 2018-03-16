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
 
#ifndef TINS_HWADDRESS_H
#define TINS_HWADDRESS_H

#include <stdint.h>
#include <iosfwd>
#include <string>
#include <cstring>
#include <tins/cxxstd.h>
#include <tins/macros.h>
#if TINS_IS_CXX11
    // std::hash
    #include <memory>
#endif // TINS_IS_CXX11

namespace Tins {
namespace Internals {

// Defined in hw_address.cpp
/**
 * \cond
 */
TINS_API std::string hw_address_to_string(const uint8_t* ptr, size_t count);

TINS_API void string_to_hw_address(const std::string& hw_addr, uint8_t* output,
                                   size_t output_size);

TINS_API bool hw_address_equal_compare(const uint8_t* start1, const uint8_t* end1,
                                      const uint8_t* start2);

TINS_API bool hw_address_lt_compare(const uint8_t* start1, const uint8_t* end1,
                                    const uint8_t* start2, const uint8_t* end2);

TINS_API bool hw_address_gt_compare(const uint8_t* start1, const uint8_t* end1,
                                    const uint8_t* start2, const uint8_t* end2);

/**
 * \endcond
 */
} // Internals

/**
 * \class HWAddress
 * \brief Represents a hardware address.
 *
 * This class represents a hardware (MAC) address. It can 
 * be constructed from it's string representation and you can
 * iterate over the bytes that compose it.
 *
 * For example:
 *
 * \code
 * // Construct it from a string.
 * HWAddress<6> address("00:01:fa:9e:1a:cd");
 *
 * // Iterate over its bytes.
 * for(auto element : address) {
 *     // element will be each of the bytes(\x00, \x01, \xfa, etc)
 * }
 * \endcode
 */
template<size_t n>
class HWAddress {
public:
    /**
     * \brief The type of the elements stored in the hardware address.
     */
    typedef uint8_t storage_type;
    
    /**
     * \brief The random access iterator type.
     */
    typedef storage_type* iterator;
    
    /**
     * \brief Const iterator type.
     */
    typedef const storage_type* const_iterator;
    
    /**
     * \brief Non-member constant indicating the amount of storage_type
     * elements in this address.
     */
    static const size_t address_size = n;

    /**
     * \brief The broadcast address.
     */
    static const HWAddress<n> broadcast;
    
    /**
     * \brief Constructor from a const storage_type*.
     * 
     * If no pointer or a null pointer is provided, the address is 
     * initialized to 00:00:00:00:00:00.
     * 
     * This constructor is very usefull when passing zero initialized
     * addresses as arguments to other functions. You can use a 
     * literal 0, which will be implicitly converted to the empty address.
     * 
     * If a pointer is provided, address_size storage_type elements 
     * are copied from the pointer, into the internal address representation.
     * 
     * \param ptr The pointer from which to construct this address.
     */
    HWAddress(const storage_type* ptr = 0) {
        if (ptr) {
            std::memcpy(buffer_, ptr, address_size);
        }
        else {
            std::memset(buffer_, 0, address_size);
        }
    }
    
    /**
     * \brief Constructs an address from a hex-notation address.
     * 
     * This constructor will parse strings in the form:
     * 
     * "00:01:da:fa:..."
     * 
     * And initialize the internal representation accordingly.
     * 
     * \param address The hex-notation address to be parsed.
     */
    HWAddress(const std::string& address) {
        Internals::string_to_hw_address(address, buffer_, n);
    }
    
    /**
     * \brief Overload provided basically for string literals.
     * 
     * This constructor takes a const char array of i elements in
     * hex-notation. \sa HWAddress::HWAddress(const std::string& address)
     * 
     * This is mostly used when providing string literals. If this where 
     * a const char*, then there would be an ambiguity when providing 
     * a null pointer. 
     * 
     * \param address The array of chars containing the hex-notation
     * cstring to be parsed.
     */
    template<size_t i>
    HWAddress(const char (&address)[i]) {
        Internals::string_to_hw_address(address, buffer_, n);
    }
    
    /**
     * \brief Copy construct from a HWAddress of length i.
     * 
     * If i is lower or equal than address_size, then i storage_type 
     * elements are copied, and the last (n - i) are initialized to 
     * the default storage_type value(0 most of the times).
     * 
     * If i is larger than address_size, then only the first address_size 
     * elements are copied.
     * 
     * \param rhs The HWAddress to be constructed from.
     */
    template<size_t i>
    HWAddress(const HWAddress<i>& rhs) {
        size_t copy_threshold = i < n ? i : n;
        for (size_t index = 0; index < n; ++index) {
            if (index < copy_threshold) {
                buffer_[index] = rhs[index];
            }
            else {
                buffer_[index] = storage_type();
            }
        }
    }
    
    /**
     * \brief Retrieves an iterator pointing to the begining of the 
     * address.
     * 
     * \return iterator.
     */
    iterator begin() {
        return buffer_;
    }
    
    /**
     * \brief Retrieves a const iterator pointing to the begining of 
     * the address.
     * 
     * \return const_iterator.
     */
    const_iterator begin() const {
        return buffer_;
    }
    
    /**
     * \brief Retrieves an iterator pointing one-past-the-end of the 
     * address.
     * 
     * \return iterator.
     */
    iterator end() {
        return buffer_ + address_size;
    }

    /**
     * \brief Retrieves a const iterator pointing one-past-the-end of 
     * the address.
     * 
     * \return const_iterator.
     */
    const_iterator end() const {
        return buffer_ + address_size;
    }
    
    /**
     * \brief Compares this HWAddress for equality.
     * 
     * \param rhs The HWAddress to be compared to.
     * 
     * \return bool indicating whether addresses are equal.
     */
    bool operator==(const HWAddress& rhs) const {
        return Internals::hw_address_equal_compare(begin(), end(), rhs.begin());
    }
    
    /**
     * \brief Compares this HWAddress for in-equality.
     * 
     * \param rhs The HWAddress to be compared to.
     * 
     * \return bool indicating whether addresses are distinct.
     */
    bool operator!=(const HWAddress& rhs) const {
        return !(*this == rhs);
    }
    
    /**
     * \brief Compares this HWAddress for less-than inequality.
     * 
     * \param rhs The HWAddress to be compared to.
     * 
     * \return bool indicating whether this address is less-than rhs.
     */
    bool operator<(const HWAddress& rhs) const {
        return Internals::hw_address_lt_compare(begin(), end(), rhs.begin(), rhs.end());
    }

    /**
     * \brief Compares this HWAddress for less-than equality.
     *
     * \param rhs The HWAddress to be compared to.
     *
     * \return bool indicating whether this address is equal or less-than rhs.
     */
    bool operator<=(const HWAddress& rhs) const {
        return !operator>(rhs);
    }

    /**
     * \brief Compares this HWAddress for greater-than inequality.
     *
     * \param rhs The HWAddress to be compared to.
     *
     * \return bool indicating whether this address is greater-than rhs.
     */
    bool operator>(const HWAddress& rhs) const {
        return Internals::hw_address_gt_compare(begin(), end(), rhs.begin(), rhs.end());
    }

    /**
     * \brief Compares this HWAddress for greater-than equality.
     *
     * \param rhs The HWAddress to be compared to.
     *
     * \return bool indicating whether this address is equal or greater-than rhs.
     */
    bool operator>=(const HWAddress& rhs) const {
        return !operator<(rhs);
    }

    /**
     * \brief Apply a mask to this address
     * 
     * \param mask The mask to be applied
     * \return The result of applying the mask to this address
     */
    HWAddress operator&(const HWAddress& mask) const {
        HWAddress<n> output = *this;
        for (size_t i = 0; i < n; ++i) {
            output[i] = output[i] & mask[i];
        }
        return output;
    }

    /**
    * \brief Apply a mask to this address
    *
    * \param mask The mask to be applied
    * \return The result of applying the mask to this address
    */
   HWAddress operator|(const HWAddress& mask) const {
       HWAddress<n> output = *this;
       for (size_t i = 0; i < n; ++i) {
           output[i] = output[i] | mask[i];
       }
       return output;
   }

   /**
    * \brief not operator
    * \return The result of applying the mask to this address
    */
   HWAddress operator~() const {
       HWAddress<n> output = *this;
       for (size_t i = 0; i < n; ++i) {
           output[i] = ~output[i];
       }
       return output;
   }

    /**
     * \brief Retrieves the size of this address.
     * 
     * This effectively returns the address_size constant.
     */
    size_t size() const {
        return address_size;
    }
    
    /**
     * \brief Indicates whether this is a broadcast address.
     */
    bool is_broadcast() const {
        return* this == broadcast;
    }
    
    /**
     * \brief Indicates whether this is a multicast address.
     */
    bool is_multicast() const {
        return (*begin() & 0x01);
    }

    /**
     * \brief Indicates whether this is an unicast address.
     */
    bool is_unicast() const {
        return !is_broadcast() && !is_multicast();
    }

    /**
     * \brief Convert this address to a hex-notation std::string address.
     * 
     * \return std::string containing the hex-notation address.
     */
    std::string to_string() const {
        return Internals::hw_address_to_string(buffer_, size());
    }

    /**
     * \brief Retrieves the i-th storage_type in this address.
     *
     * \param i The element to retrieve.
     */
    storage_type operator[](size_t i) const {
        return begin()[i];
    }

    /**
     * \brief Retrieves the i-th storage_type in this address.
     *
     * \param i The element to retrieve.
     */
    storage_type& operator[](size_t i) {
        return begin()[i];
    }
    
    /**
     * \brief Writes this HWAddress in hex-notation to a std::ostream.
     * 
     * \param os The stream in which to write the address.
     * \param addr The parameter to be written.
     * \return std::ostream& pointing to the os parameter.
     */
    friend std::ostream& operator<<(std::ostream& os, const HWAddress& addr) {
        return os << addr.to_string();
    }
    
    /**
     * \brief Helper function which copies the address into an output
     * iterator.
     * 
     * This is the same as:
     * 
     * std::copy(begin(), end(), iter);
     * 
     * But since some PDUs return a HWAddress<> by value, this function
     * can be used to avoid temporaries. 
     * 
     * \param output The output iterator in which to store this address.
     * \return OutputIterator pointing to one-past the last position
     * written.
     */
    template<typename OutputIterator>
    OutputIterator copy(OutputIterator output) const {
        for (const_iterator iter = begin(); iter != end(); ++iter) {
            *output++ = *iter;
        }
        return output;
    }
private:
    static HWAddress<n> make_broadcast_address() {
        // Build a buffer made of n 0xff bytes
        uint8_t buffer[n];
        for (size_t i = 0; i < n; ++i) {
            buffer[i] = 0xff;
        }
        return HWAddress<n>(buffer);
    }

    storage_type buffer_[n];
};

template<size_t n>
const HWAddress<n> HWAddress<n>::broadcast = make_broadcast_address();

} // namespace Tins

#if TINS_IS_CXX11
namespace std {

// Specialization of std::hash for HWAddress
template<size_t n>
struct hash<Tins::HWAddress<n>> {
    size_t operator()(const Tins::HWAddress<n>& addr) const {
        return std::hash<std::string>()(addr.to_string());
    }
};

} // namespace std
#endif // TINS_IS_CXX11

#endif // TINS_HWADDRESS_H
