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

#ifndef TINS_ADDRESS_RANGE
#define TINS_ADDRESS_RANGE

#include <stdexcept>
#include <iterator>
#include "endianness.h"
#include "internals.h"

namespace Tins {
/**
 * \brief AddressRange iterator class.
 */
template<typename Address>
class AddressRangeIterator : public std::iterator<std::forward_iterator_tag, const Address> {
public:
    typedef typename std::iterator<std::forward_iterator_tag, const Address>::value_type value_type;

    struct end_iterator {

    };

    /**
     * Constructs an iterator.
     *
     * \param first The address held by this iterator.
     */
    AddressRangeIterator(const value_type &addr)
    : addr(addr), reached_end(false)
    {

    }

    /**
     * Constructs an iterator.
     *
     * \param first The address held by this iterator.
     */
    AddressRangeIterator(const value_type &address, end_iterator)
    : addr(address)
    {
        reached_end = Internals::increment(addr);
    }

    /**
     * Retrieves the current address pointed by this iterator.
     */
    const value_type& operator*() const {
        return addr;
    }

    /**
     * Retrieves a pointer to the current address pointed by this iterator.
     */
    const value_type* operator->() const {
        return &addr;
    }

    /**
     * Compares two iterators for equality.
     *
     * \param rhs The iterator with which to compare.
     */
    bool operator==(const AddressRangeIterator &rhs) const {
        return reached_end == rhs.reached_end && addr == rhs.addr;
    }

    /**
     * Compares two iterators for inequality.
     *
     * \param rhs The iterator with which to compare.
     */
    bool operator!=(const AddressRangeIterator &rhs) const {
        return !(*this == rhs);
    }

    /**
     * Increments this iterator.
     */
    AddressRangeIterator& operator++() {
        reached_end = Internals::increment(addr);
        return *this;
    }

    /**
     * Increments this iterator.
     */
    AddressRangeIterator operator++(int) {
        AddressRangeIterator copy(*this);
        (*this)++;
        return copy;
    }
private:
    Address addr;
    bool reached_end;
};

/**
 * \brief Represents a range of addresses.
 *
 * This class provides a begin()/end() interface which allows
 * iterating through every address stored in it. 
 *
 * Note that when iterating a range that was created using
 * operator/(IPv4Address, int) and the analog for IPv6, the 
 * network and broadcast addresses are discarded:
 *
 * \code
 * auto range = IPv4Address("192.168.5.0") / 24;
 * for(const auto &addr : range) {
 *     // process 192.168.5.1-254, .0 and .255 are discarded
 *     process(addr);
 * }
 *
 * // That's only valid for iteration, not for AddressRange<>::contains
 * 
 * assert(range.contains("192.168.5.0")); // works
 * assert(range.contains("192.168.5.255")); // works
 * \endcode
 *
 * Ranges created using AddressRange(address_type, address_type) 
 * will allow the iteration over the entire range:
 *
 * \code
 * AddressRange<IPv4Address> range("192.168.5.0", "192.168.5.255");
 * for(const auto &addr : range) {
 *     // process 192.168.5.0-255, no addresses are discarded
 *     process(addr);
 * }
 * 
 * assert(range.contains("192.168.5.0")); // still valid
 * assert(range.contains("192.168.5.255")); // still valid
 * \endcode
 * 
 */
template<typename Address>
class AddressRange {
public:
    /**
     * The type of addresses stored in the range.
     */
    typedef Address address_type;

    /**
     * The iterator type.
     */
    typedef AddressRangeIterator<address_type> const_iterator;

    /**
     * \brief The iterator type.
     *
     * This is the same type as const_iterator, since the
     * addresses stored in this range are read only.
     */
    typedef const_iterator iterator;

    /**
     * \brief Constructs an address range from two addresses.
     *
     * The range will consist of the addresses [first, last].
     *
     * If only_hosts is true, then the network and broadcast addresses
     * will not be available when iterating the range. 
     *
     * If last < first, an std::runtime_error exception is thrown.
     * 
     * \param first The first address in the range.
     * \param last The last address(inclusive) in the range.
     * \param only_hosts Indicates whether only host addresses
     * should be accessed when using iterators.
     */
    AddressRange(const address_type &first, const address_type &last, bool only_hosts = false)
    : first(first), last(last), only_hosts(only_hosts)
    {
        if(last < first)
            throw std::runtime_error("Invalid address range");
    }

    /**
     * \brief Creates an address range from a base address
     * and a network mask.
     *
     * \param first The base address.
     * \param mask The network mask to be used.
     */
    static AddressRange from_mask(const address_type &first, const address_type &mask) {
        return AddressRange<address_type>(
            first, 
            Internals::last_address_from_mask(first, mask), 
            true
        );
    }

    /**
     * \brief Indicates whether an address is included in this range.
     * \param addr The address to test.
     * \return a bool indicating whether the address is in the range.
     */
    bool contains(const address_type &addr) const {
        return (first < addr && addr < last) || addr == first || addr == last;
    }

    /**
     * \brief Returns an interator to the beginning of this range.
     * \brief const_iterator pointing to the beginning of this range.
     */
    const_iterator begin() const {
        address_type addr = first;
        if(only_hosts)
            Internals::increment(addr);
        return const_iterator(addr);
    }

    /**
     * \brief Returns an interator to the end of this range.
     * \brief const_iterator pointing to the end of this range.
     */
    const_iterator end() const {
        address_type addr = last;
        if(only_hosts)
            Internals::decrement(addr);
        return const_iterator(addr, typename const_iterator::end_iterator());
    }

    /**
     * \brief Indicates whether this range is iterable.
     *
     * Iterable ranges are those for which there is at least one 
     * address that could represent a host. For IPv4 ranges, a /31 or
     * /32 ranges does not contain any, therefore it's not iterable.
     * The same is true for /127 and /128 IPv6 ranges.
     *
     * If is_iterable returns false for a range, then iterating it
     * through the iterators returned by begin() and end() is 
     * undefined. 
     * 
     * \return bool indicating whether this range is iterable.
     */
    bool is_iterable() const {
        // Since first < last, it's iterable
        if(!only_hosts)
            return true;
        // We need that distance(first, last) >= 4
        address_type addr(first);
        for(int i = 0; i < 3; ++i) {
            // If there's overflow before the last iteration, we're done
            if(Internals::increment(addr) && i != 2)
                return false;
        }
        // If addr <= last, it's OK.
        return addr < last || addr == last;
    }
private:
    address_type first, last;
    bool only_hosts;
};

/**
 * An IPv4 address range.
 */
typedef AddressRange<IPv4Address> IPv4Range;

/**
 * An IPv6 address range.
 */
typedef AddressRange<IPv6Address> IPv6Range;

/**
 * \brief Constructs an AddressRange from a base address and a mask.
 * \param addr The range's first address.
 * \param mask The bit-length of the prefix.
 */
template<size_t n>
AddressRange<HWAddress<n> > operator/(const HWAddress<n> &addr, int mask) {
    if(mask > 48)
        throw std::logic_error("Prefix length cannot exceed 48");
    HWAddress<n> last_addr;
    typename HWAddress<n>::iterator it = last_addr.begin();
    while(mask > 8) {
        *it = 0xff;
        ++it;
        mask -= 8;
    }
    *it = 0xff << (8 - mask);
    return AddressRange<HWAddress<6> >::from_mask(addr, last_addr);
}

/**
 * \brief Constructs an IPv6Range from a base IPv6Address and a mask.
 * \param addr The range's first address.
 * \param mask The bit-length of the prefix.
 */
IPv6Range operator/(const IPv6Address &addr, int mask);

/**
 * \brief Constructs an IPv4Range from a base IPv4Address and a mask.
 * \param addr The range's first address.
 * \param mask The bit-length of the prefix.
 */
IPv4Range operator/(const IPv4Address &addr, int mask);
} // namespace Tins

#endif // TINS_ADDRESS_RANGE
