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
 
#ifndef TINS_HWADDRESS_H
#define TINS_HWADDRESS_H

#include <stdint.h>
#include <stdexcept>
#include <iterator>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace Tins {
template<size_t n, typename Storage = uint8_t>
class HWAddress {
public:
    typedef Storage storage_type;
    typedef storage_type* iterator;
    typedef const storage_type* const_iterator;
    static const size_t address_size = n;
    
    HWAddress() {
        std::fill(begin(), end(), storage_type());
    }
    
    HWAddress(const storage_type* ptr) {
        std::copy(ptr, ptr + address_size, buffer);
    }
    
    HWAddress(const std::string &address) {
        convert(address, buffer);
    }
    
    HWAddress(const char *address) {
        convert(address, buffer);
    }
    
    template<size_t i>
    HWAddress(const HWAddress<i> &rhs) {
        std::copy(
            rhs.begin(),
            rhs.begin() + std::min(i, n),
            begin()
        );
    }
    
    HWAddress& operator=(const std::string &address) {
        convert(address, buffer);
    }
    
    iterator begin() {
        return buffer;
    }
    
    const_iterator begin() const {
        return buffer;
    }
    
    iterator end() {
        return buffer + address_size;
    }
    
    const_iterator end() const {
        return buffer + address_size;
    }
    
    bool operator==(const HWAddress &rhs) const {
        return std::equal(begin(), end(), rhs.begin());
    }
    
    bool operator!=(const HWAddress &rhs) const {
        return !(*this == rhs);
    }
    
    const size_t size() const {
        return address_size;
    }
    
    friend std::ostream &operator<<(std::ostream &os, const HWAddress &addr) {
        std::transform(
            addr.buffer, 
            addr.buffer + HWAddress::address_size - 1,
            std::ostream_iterator<std::string>(os, ":"),
            &HWAddress::to_string
        );
        return os << to_string(addr.buffer[HWAddress::address_size-1]);
    }
private:
    template<typename OutputIterator>
    static void convert(const std::string &hw_addr, OutputIterator output);
    
    static std::string to_string(storage_type element) {
        std::ostringstream oss;
        oss << std::hex;
        if(element < 0x10)
            oss << '0';
        oss << (unsigned)element;
        return oss.str();
    }

    storage_type buffer[n];
};

template<size_t n, typename Storage>
template<typename OutputIterator>
void HWAddress<n, Storage>::convert(const std::string &hw_addr, 
  OutputIterator output) 
{
    unsigned i(0);
    storage_type tmp;
    while(i < hw_addr.size()) {
        const unsigned end = i+2;
        tmp = storage_type();
        while(i < end) {
            if(hw_addr[i] >= 'a' && hw_addr[i] <= 'f')
                tmp = (tmp << 4) | (hw_addr[i] - 'a' + 10);
            else if(hw_addr[i] >= '0' && hw_addr[i] <= '9')
                tmp = (tmp << 4) | (hw_addr[i] - '0');
            else if(hw_addr[i] == ':')
                break;
            else
                throw std::runtime_error("Invalid byte found");
            i++;
        }
        *(output++) = tmp;
        if(i < hw_addr.size()) {
            if(hw_addr[i] == ':')
                i++;
            else
                throw std::runtime_error("Invalid separator");
        }
    }
}
}
#endif // TINS_HWADDRESS_H
