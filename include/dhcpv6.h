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

#ifndef TINS_DHCPV6_H
#define TINS_DHCPV6_H

#include <list>
#include "pdu.h"
#include "endianness.h"
#include "small_uint.h"
#include "ipv6_address.h"
#include "pdu_option.h"

namespace Tins {    
/**
 * Represents a DHCPv6 PDU.
 */
class DHCPv6 : public PDU {
public:
    /**
     * Represents a DHCPv6 option. 
     */
    class dhcpv6_option {
    public:
        typedef std::vector<uint8_t> container_type;
        typedef container_type::value_type data_type;
        typedef uint16_t option_type;

        /**
         * \brief Constructs a PDUOption.
         * \param opt The option type.
         * \param length The option's data length.
         * \param data The option's data(if any).
         */
        dhcpv6_option(option_type opt = 0, size_t length = 0, const data_type *data = 0) 
        : option_(opt), option_size_(length) {
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
        dhcpv6_option(option_type opt, ForwardIterator start, ForwardIterator end) 
        : option_(opt), option_size_(std::distance(start, end))
        {
            value_.insert(value_.end(), start, end);
        }
        
        /**
         * Retrieves this option's type.
         * \return uint8_t containing this option's size.
         */
        uint16_t option() const {
            return option_;
        }
        
        /**
         * Sets this option's type
         * \param opt The option type to be set.
         */
        void option(uint16_t opt) {
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
         * Retrieves the length of this option's data.
         */
        uint16_t data_size() const {
            return option_size_;
        }
    private:
        option_type option_;
        uint16_t option_size_;
        container_type value_;
    };

    /**
     * The type used to store the DHCPv6 options.
     */
    typedef std::list<dhcpv6_option> options_type;

    /**
     * The type used to store IP addresses.
     */
    typedef IPv6Address ipaddress_type;
    
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DHCPv6;

    /**
     * Default constructor.
     */
    DHCPv6();
    
    /**
     * \brief Constructor which constructs a DHCPv6 object from a buffer 
     * and adds all identifiable PDUs found in the buffer as children 
     * of this one.
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    DHCPv6(const uint8_t *buffer, uint32_t total_sz);

    // Getters
    /**
     * \brief Getter for the message type field.
     *
     * \return The stored message type field.
     */
    uint8_t msg_type() const { return header_data[0]; }
    
    /**
     * \brief Getter for the hop count field.
     *
     * \return The stored hop count field.
     */
    uint8_t hop_count() const { return header_data[1]; }
    
    /**
     * \brief Getter for the transaction id field.
     *
     * \return The stored transaction id field.
     */
    small_uint<24> transaction_id() const { 
        return (header_data[1] << 16) | (header_data[2] << 8) | header_data[3];
    }

    /**
     * \brief Getter for the peer address field.
     *
     * \return The stored peer address field.
     */
    const ipaddress_type &peer_address() const { return peer_addr; }
    
    /**
     * \brief Getter for the link address field.
     *
     * \return The stored link address field.
     */
    const ipaddress_type &link_address() const { return link_addr; }

    // Setters
    /**
     * \brief Setter for the message type field.
     *
     * \param type The new message type.
     */
    void msg_type(uint8_t type);
    
    /**
     * \brief Setter for the hop count field.
     *
     * \param count The new hop count.
     */
    void hop_count(uint8_t count);
    
    /**
     * \brief Setter for the transaction id field.
     *
     * \param id The new transaction id.
     */
    void transaction_id(small_uint<24> id);
    
    /**
     * \brief Setter for the peer address field.
     *
     * \param count The new peer address.
     */
    void peer_address(const ipaddress_type &addr);
    
    /**
     * \brief Setter for the link address field.
     *
     * \param count The new link address.
     */
    void link_address(const ipaddress_type &addr);
    
    // Other stuff
    
    /**
     * Indicates whether this is a relay agent/server message
     */
    bool is_relay_message() const;
    
    /**
     * \brief Adds a DHCPv6 option.
     * 
     * The option is added after the last option in the option 
     * fields.
     * 
     * \param option The option to be added
     */
    void add_option(const dhcpv6_option &option);
    
    /**
     * \brief Searchs for an option that matchs the given flag.
     * 
     * If the option is not found, a null pointer is returned. 
     * Deleting the returned pointer will result in <b>undefined 
     * behaviour</b>.
     * 
     * \param id The option identifier to be searched.
     */
    const dhcpv6_option *search_option(uint16_t id) const;
    
    // PDU stuff
    
    /**
     * \brief Returns the header size.
     *
     * This metod overrides PDU::header_size. \sa PDU::header_size
     */
    uint32_t header_size() const;
    
    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }
    
    /**
     * \sa PDU::clone
     */
    DHCPv6 *clone() const {
        return new DHCPv6(*this);
    }
private:
    void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *);
    uint8_t* write_option(const dhcpv6_option &option, uint8_t* buffer) const;

    uint8_t header_data[4];
    uint32_t options_size;
    ipaddress_type link_addr, peer_addr;
    options_type options_;
};    
}

#endif // TINS_DHCPV6_H
