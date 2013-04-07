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
    : option_(opt), size_(length), value_(data, data + (data ? length : 0)) {
        
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
    : option_(opt), size_(std::distance(start, end)), value_(start, end) {
        
    }
    
    /**
     * \brief Constructs a PDUOption from iterators, which 
     * indicate the data to be stored in it.
     * 
     * The length parameter indicates the contents of the length field
     * when this option is serialized. Note that this can be different
     * to std::distance(start, end).
     * 
     * \param opt The option type.
     * \param length The length of this option.
     * \param start The beginning of the option data.
     * \param end The end of the option data.
     */
    template<typename ForwardIterator>
    PDUOption(option_type opt, size_t length, ForwardIterator start, ForwardIterator end) 
    : option_(opt), size_(length), value_(start, end) {
        
    }
    
    /**
     * Retrieves this option's type.
     * \return uint8_t containing this option's size.
     */
    option_type option() const {
        return option_;
    }
    
    /**
     * Sets this option's type
     * \param opt The option type to be set.
     */
    void option(option_type opt) {
        option_ = opt;
    }
    
    /**
     * Retrieves this option's data.
     * 
     * If this method is called when data_size() == 0, 
     * dereferencing the returned pointer will result in undefined
     * behaviour.
     * 
     * \return const data_type& containing this option's value.
     */
    const data_type *data_ptr() const {
        return &*value_.begin();
    }
    
    /**
     * \brief Retrieves the length of this option's data.
     * 
     * This is the actual size of the data.
     */
    size_t data_size() const {
        return value_.size();
    }
    
    /**
     * \brief Retrieves the data length field.
     * 
     * This may be different to the actual size of the data. 
     * 
     * \sa data_size.
     */
    size_t length_field() const {
        return size_;
    }
private:
    option_type option_;
    uint16_t size_;
    container_type value_;
};
} // namespace Tins
#endif // TINS_PDU_OPTION_H
