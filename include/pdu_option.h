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

#ifndef TINS_PDU_OPTION_H
#define TINS_PDU_OPTION_H

#include <vector>
#include <iterator>
#include <stdint.h>

namespace Tins {
/**
 * \brief Exception thrown when an option is not found.
 */
class option_not_found : public std::exception {
public:
    const char* what() const throw() {
        return "Option not found";
    }
};
    
/**
 * \class PDUOption
 * \brief Represents a PDU option field.
 * 
 * Several PDUs, such as TCP, IP, Dot11 or DHCP contain options. All
 * of them behave exactly the same way. This class represents those
 * options.
 * 
 * The OptionType template parameter indicates the type that will be
 * used to store this option's identifier.
 * 
 * The Container template parameter indicates the container which will
 * be used to store this option's data. The container <b>must</b>
 * store data sequentially. std::vector<uint8_t> is the default
 * container.
 */
template<typename OptionType, class Container = std::vector<uint8_t> >
class PDUOption {
public:
    typedef Container container_type;
    typedef typename container_type::value_type data_type;
    typedef OptionType option_type;

    /**
     * \brief Constructs a PDUOption.
     * \param opt The option type.
     * \param length The option's data length.
     * \param data The option's data(if any).
     */
    PDUOption(option_type opt = option_type(), size_t length = 0, const data_type *data = 0) 
    : option_(opt) {
        value_.push_back(length);
        if(data)
            value_.insert(value_.end(), data, data + length);
    }
    
    /**
     * \brief Constructs a PDUOption from iterators, which 
     * indicate the data to be stored in it.
     * 
     * \param opt The option type.
     * \param start The beginning of the option data.
     * \param end The end of the option data.
     */
    template<typename ForwardIterator>
    PDUOption(option_type opt, ForwardIterator start, ForwardIterator end) 
    : option_(opt) {
        value_.push_back(std::distance(start, end));
        value_.insert(value_.end(), start, end);
    }
    
    /**
     * Retrieves this option's type.
     * \return uint8_t containing this option's size.
     */
    option_type option() const {
        return option_;
    }
    
    /**
     * Retrieves this option's data.
     * 
     * If this method is called when data_size() == 0, 
     * dereferencing the returned pointer will result in undefined
     * behaviour.
     * 
     * \return const value_type& containing this option's value.
     */
    const data_type *data_ptr() const {
        return &*(++value_.begin());
        
        //return &value_[1];
    }
    
    /**
     * Retrieves the length of this option's data.
     */
    size_t data_size() const {
        return value_.empty() ? 0 : (value_.size() - 1);
    }
private:
    option_type option_;
    container_type value_;
};
} // namespace Tins
#endif // TINS_PDU_OPTION_H
