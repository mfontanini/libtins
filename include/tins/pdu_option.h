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

#ifndef TINS_PDU_OPTION_H
#define TINS_PDU_OPTION_H

#include <vector>
#include <string>
#include <cstring>
#include <stdint.h>
#include <tins/exceptions.h>
#include <tins/detail/type_traits.h>

namespace Tins {

class IPv4Address;
class IPv6Address;
template <size_t n>
class HWAddress;

/**
 * \cond
 */
template <typename OptionType, typename PDUType>
class PDUOption;

namespace Internals {
    namespace Converters {
        uint8_t convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                        type_to_type<uint8_t>);
        int8_t convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                        type_to_type<int8_t>);
        uint16_t convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                         type_to_type<uint16_t>);
        uint32_t convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                         type_to_type<uint32_t>);
        uint64_t convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                         type_to_type<uint64_t>);
        HWAddress<6> convert(const uint8_t* ptr, uint32_t data_size,
                             PDU::endian_type endian, type_to_type<HWAddress<6> >);
        IPv4Address convert(const uint8_t* ptr, uint32_t data_size,
                            PDU::endian_type endian, type_to_type<IPv4Address>);
        IPv6Address convert(const uint8_t* ptr, uint32_t data_size, PDU::endian_type endian,
                            type_to_type<IPv6Address>);
        std::string convert(const uint8_t* ptr, uint32_t data_size,
                            PDU::endian_type endian, type_to_type<std::string>);
        std::vector<float> convert(const uint8_t* ptr, uint32_t data_size,
                                   PDU::endian_type endian, type_to_type<std::vector<float> >);
        std::vector<uint8_t> convert(const uint8_t* ptr, uint32_t data_size,
                                     PDU::endian_type endian, type_to_type<std::vector<uint8_t> >);
        std::vector<uint16_t> convert(const uint8_t* ptr, uint32_t data_size,
                                      PDU::endian_type endian,
                                      type_to_type<std::vector<uint16_t> >);
        std::vector<uint32_t> convert(const uint8_t* ptr, uint32_t data_size,
                                      PDU::endian_type endian,
                                      type_to_type<std::vector<uint32_t> >);
        std::vector<IPv4Address> convert(const uint8_t* ptr, uint32_t data_size,
                                         PDU::endian_type endian,
                                         type_to_type<std::vector<IPv4Address> >);
        std::vector<IPv6Address> convert(const uint8_t* ptr, uint32_t data_size,
                                         PDU::endian_type endian,
                                         type_to_type<std::vector<IPv6Address> >);
        std::vector<std::pair<uint8_t, uint8_t> > convert(const uint8_t* ptr, uint32_t data_size,
                                                          PDU::endian_type endian,
                                        type_to_type<std::vector<std::pair<uint8_t, uint8_t> > >);
        std::pair<uint8_t, uint8_t> convert(const uint8_t* ptr, uint32_t data_size,
                                            PDU::endian_type endian,
                                            type_to_type<std::pair<uint8_t, uint8_t> >);
        std::pair<uint16_t, uint32_t> convert(const uint8_t* ptr, uint32_t data_size,
                                              PDU::endian_type endian,
                                              type_to_type<std::pair<uint16_t, uint32_t> >);
        std::pair<uint32_t, uint32_t> convert(const uint8_t* ptr, uint32_t data_size,
                                              PDU::endian_type endian,
                                              type_to_type<std::pair<uint32_t, uint32_t> >);
    } // Converters
    
    struct converter {
        template <typename T, typename X, typename PDUType>
        static T do_convert(const PDUOption<X, PDUType>& opt, type_to_type<T>) {
            return T::from_option(opt);
        }

        template <typename U, typename X, typename PDUType>
        static U do_convert(const PDUOption<X, PDUType>& opt, type_to_type<uint8_t> type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType>
        static U do_convert(const PDUOption<X, PDUType>& opt, type_to_type<int8_t> type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType>
        static U do_convert(const PDUOption<X, PDUType>& opt, type_to_type<uint16_t> type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType>
        static U do_convert(const PDUOption<X, PDUType>& opt, type_to_type<uint32_t> type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType>
        static U do_convert(const PDUOption<X, PDUType>& opt, type_to_type<uint64_t> type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType>
        static U do_convert(const PDUOption<X, PDUType>& opt, type_to_type<HWAddress<6> > type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType>
        static U do_convert(const PDUOption<X, PDUType>& opt, type_to_type<IPv4Address> type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType>
        static U do_convert(const PDUOption<X, PDUType>& opt, type_to_type<IPv6Address> type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType>
        static U do_convert(const PDUOption<X, PDUType>& opt,
                            type_to_type<std::string> type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType, typename Z>
        static U do_convert(const PDUOption<X, PDUType>& opt,
                            type_to_type<std::vector<Z> > type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename U, typename X, typename PDUType, typename Z, typename W>
        static U do_convert(const PDUOption<X, PDUType>& opt,
                            type_to_type<std::pair<Z, W> > type) {
            return Converters::convert(opt.data_ptr(), opt.data_size(),
                                       PDUType::endianness, type);
        }

        template <typename T, typename X, typename PDUType>
        static T convert(const PDUOption<X, PDUType>& opt) {
            return do_convert<T>(opt, type_to_type<T>());
        }
    };
}

/**
 * \endcond
 */

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
 */
template <typename OptionType, typename PDUType>
class PDUOption {
private:
    static const int small_buffer_size = 8;
public:
    typedef uint8_t data_type;
    typedef OptionType option_type;

    /**
     * \brief Constructs a PDUOption.
     * \param opt The option type.
     * \param length The option's data length.
     * \param data The option's data(if any).
     */
    PDUOption(option_type opt = option_type(), 
              size_t length = 0,
              const data_type* data = 0) 
    : option_(opt), size_(static_cast<uint16_t>(length)), real_size_(0) {
        if (data != 0) {
            set_payload_contents(data, data + length);
        }
    }
    
    /**
     * \brief Copy constructor.
     * \param rhs The PDUOption to be copied.
     */
    PDUOption(const PDUOption& rhs) {
        real_size_ = 0;
        *this = rhs;
    }
    
    #if TINS_IS_CXX11
    /**
     * \brief Move constructor.
     * \param rhs The PDUOption to be moved.
     */
    PDUOption(PDUOption&& rhs) TINS_NOEXCEPT {
        real_size_ = 0;
        *this = std::move(rhs);
    }
    
    /**
     * \brief Move assignment operator.
     * \param rhs The PDUOption to be moved.
     */
    PDUOption& operator=(PDUOption&& rhs) TINS_NOEXCEPT {
        option_ = rhs.option_;
        size_ = rhs.size_;
        if (real_size_ > small_buffer_size) {
            delete[] payload_.big_buffer_ptr;
        }
        real_size_ = rhs.real_size_;
        if (real_size_ > small_buffer_size) {
            payload_.big_buffer_ptr = 0;
            std::swap(payload_.big_buffer_ptr, rhs.payload_.big_buffer_ptr);
            rhs.real_size_ = 0;
        }
        else {
            std::memcpy(payload_.small_buffer, rhs.data_ptr(), rhs.data_size());
        }
        return *this;
    }
    
    #endif // TINS_IS_CXX11
    
    /**
     * \brief Copy assignment operator.
     * \param rhs The PDUOption to be copied.
     */
    PDUOption& operator=(const PDUOption& rhs) {
        option_ = rhs.option_;
        size_ = rhs.size_;
        if (real_size_ > small_buffer_size) {
            delete[] payload_.big_buffer_ptr;
        }
        real_size_ = rhs.real_size_;
        set_payload_contents(rhs.data_ptr(), rhs.data_ptr() + rhs.data_size());
        return* this;
    }
    
    /**
     * \brief Destructor.
     */
    ~PDUOption() {
        if (real_size_ > small_buffer_size) {
            delete[] payload_.big_buffer_ptr;
        }
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
    : option_(opt), size_(static_cast<uint16_t>(std::distance(start, end))) {
        set_payload_contents(start, end);
    }
    
    /**
     * \brief Constructs a PDUOption from iterators, which 
     * indicate the data to be stored in it.
     * 
     * The length parameter indicates the contents of the length field
     * when this option is serialized. Note that this can be different
     * to std::distance(start, end).
     * 
     * \sa length_field
     * 
     * \param opt The option type.
     * \param length The length of this option.
     * \param start The beginning of the option data.
     * \param end The end of the option data.
     */
    template<typename ForwardIterator>
    PDUOption(option_type opt, uint16_t length, ForwardIterator start, ForwardIterator end) 
    : option_(opt), size_(length) {
        set_payload_contents(start, end);
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
    const data_type* data_ptr() const {
        return real_size_ <= small_buffer_size ?
               payload_.small_buffer : 
               payload_.big_buffer_ptr;
    }
    
    /**
     * \brief Retrieves the length of this option's data.
     * 
     * This is the actual size of the data.
     */
    size_t data_size() const {
        return real_size_;
    }
    
    /**
     * \brief Retrieves the data length field.
     * 
     * This is what the size field will contain when this option is 
     * serialized. It can differ from the actual data size. 
     * 
     * This will be equal to data_size unless the constructor that takes
     * both a data length and two iterators is used.

     * 
     * \sa data_size.
     */
    size_t length_field() const {
        return size_;
    }
    
    /**
     * \brief Constructs a T from this PDUOption.
     * 
     * Use this method to convert a PDUOption to the specific type that
     * represents it. For example, if you know an option is of type
     * PDU::SACK, you could use option.to<TCP::sack_type>().
     */
    template<typename T>
    T to() const {
        return Internals::converter::convert<T>(*this);
    }
private:
    template<typename ForwardIterator>
    void set_payload_contents(ForwardIterator start, ForwardIterator end) {
        size_t total_size = std::distance(start, end);
        if (total_size > 65535) {
            throw option_payload_too_large();
        }
        real_size_ = static_cast<uint16_t>(total_size);
        if (real_size_ <= small_buffer_size) {
            if (total_size > 0) {
                std::memcpy(payload_.small_buffer, &*start, total_size);
            }
        }
        else {
            payload_.big_buffer_ptr = new data_type[real_size_];
            uint8_t* ptr = payload_.big_buffer_ptr;
            while (start < end) {
                *ptr = *start;
                ++ptr;
                ++start;
            }
        }
    }

    option_type option_;
    uint16_t size_, real_size_;
    union {
        data_type small_buffer[small_buffer_size];
        data_type* big_buffer_ptr;
    } payload_;
};

namespace Internals {
/*
 * \cond
 */

template <typename Option, typename Container>
typename Container::iterator find_option(Container& cont, typename Option::option_type type) {
    typename Container::iterator iter;
    for (iter = cont.begin(); iter != cont.end(); ++iter) {
        if (iter->option() == type) {
            break;
        }
    }
    return iter;
}

template <typename Option, typename Container>
typename Container::const_iterator find_option_const(const Container& cont,
                                                     typename Option::option_type type) {
    typename Container::const_iterator iter;
    for (iter = cont.begin(); iter != cont.end(); ++iter) {
        if (iter->option() == type) {
            break;
        }
    }
    return iter;
}

/*
 * \endcond
 */
} // Internals

} // namespace Tins
#endif // TINS_PDU_OPTION_H
