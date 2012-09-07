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

#ifndef TINS_TCP_H
#define TINS_TCP_H


#include <list>
#include <vector>
#include <stdint.h>
#include <stdexcept>
#include <utility>
#include "pdu.h"
#include "endianness.h"
#include "small_uint.h"

namespace Tins {
    /**
     * \brief Class that represents an TCP PDU.
     *
     * TCP is the representation of the TCP PDU. Instances of this class
     * must be sent over a level 3 PDU, this will otherwise fail.
     */

    class TCP : public PDU {
    public:
        /**
         * This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::TCP;
    
        /**
         * \brief TCP flags enum.
         *
         * These flags identify those supported by the TCP PDU.
         */
        enum Flags {
            FIN,
            SYN,
            RST,
            PSH,
            ACK,
            URG,
            ECE,
            CWR
        };

        /**
         * \brief TCP options enum.
         *
         * This enum identifies valid options supported by TCP PDU.
         */

        enum Option {
            EOL     = 0,
            NOP     = 1,
            MSS     = 2,
            WSCALE  = 3,
            SACK_OK = 4,
            SACK    = 5,
            TSOPT   = 8,
            ALTCHK  = 14
        };
        
        /**
         * \brief Alternate checksum enum.
         */
        enum AltChecksums {
            CHK_TCP,
            CHK_8FLETCHER,
            CHK_16FLETCHER
        };
        
        /**
         * \brief Class that represents a TCP option field.
         */
        class TCPOption {
        public:
            /**
             * \brief Constructs a TCPOption.
             * \param opt The option type.
             * \param length The option's data length.
             * \param data The option's data(if any).
             */
            TCPOption(uint8_t opt = 0, uint8_t length = 0, const uint8_t *data = 0) 
            : option_(opt) {
                value_.push_back(length);
                if(data)
                    value_.insert(value_.end(), data, data + length);
            }
            
            /**
             * Constructs a TCPOption from iterators, which indicate
             * the data to be stored in it.
             * \param opt The option type.
             * \param start The beginning of the option data.
             * \param end The end of the option data.
             */
            template<typename ForwardIterator>
            TCPOption(uint8_t opt, ForwardIterator start, ForwardIterator end) 
            : option_(opt), value_(start, end) {
                
            }
            
            /**
             * Retrieves this option's type.
             * \return uint8_t containing this option's size.
             */
            uint8_t option() const {
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
            const uint8_t *data_ptr() const {
                return &value_[1];
            }
            
            /**
             * Retrieves the length of this option's data.
             */
            size_t data_size() const {
                return value_.size() - 1;
            }

            /**
             * \brief Writes the option into a buffer.
             * \param buffer The buffer in which to write the option.
             * \return The buffer pointer incremented by the size of this option.
             */
            uint8_t *write(uint8_t *buffer);
        private:
            typedef std::vector<uint8_t> data_type;
        
            uint8_t option_;
            data_type value_;
        };

        /**
         * The type used to store the options.
         */
        typedef std::vector<TCPOption> options_type;
        
        /**
         * The type used to store the sack option.
         */
        typedef std::vector<uint32_t> sack_type;

        /**
         * \brief Exception thrown when an option is not found.
         */
        class OptionNotFound : public std::exception {
        public:
            const char* what() const throw() {
                return "Option not found";
            }
        };

        /**
         * \brief TCP constructor.
         *
         * Creates an instance of TCP. Destination and source port can
         * be provided, otherwise both will be 0.
         * \param dport Destination port.
         * \param sport Source port.
         * */
        TCP(uint16_t dport = 0, uint16_t sport = 0);

        /**
         * \brief Constructor which creates an TCP object from a buffer 
         * and adds all identifiable PDUs found in the buffer as children
         * of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        TCP(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the destination port field.
         *
         * \return The destination port in an uint16_t.
         */
        uint16_t dport() const { return Endian::be_to_host(_tcp.dport); }

        /**
         * \brief Getter for the source port field.
         *
         * \return The source port in an uint16_t.
         */
        uint16_t sport() const { return Endian::be_to_host(_tcp.sport); }

        /**
         * \brief Getter for the sequence number field.
         *
         * \return The sequence number in an uint32_t.
         */
        uint32_t seq() const { return Endian::be_to_host(_tcp.seq); }

        /**
         * \brief Getter for the acknowledge number field.
         *
         * \return The acknowledge number in an uint32_t.
         */
        uint32_t ack_seq() const { return Endian::be_to_host(_tcp.ack_seq); }

        /**
         * \brief Getter for the window size field.
         *
         * \return The window size in an uint32_t.
         */
        uint16_t window() const { return Endian::be_to_host(_tcp.window); }

        /**
         * \brief Getter for the checksum field.
         *
         * \return The checksum field in an uint16_t.
         */
        uint16_t check() const { return Endian::be_to_host(_tcp.check); }

        /**
         * \brief Getter for the urgent pointer field.
         *
         * \return The urgent pointer in an uint16_t.
         */
        uint16_t urg_ptr() const { return Endian::be_to_host(_tcp.urg_ptr); }

        /**
         * \brief Getter for the data offset field.
         *
         * \return Data offset in an uint8_t.
         */
        small_uint<4> data_offset() const { return this->_tcp.doff; }

        /**
         * \brief Getter for the option list.
         * 
         * \return The options list.
         */
        const options_type &options() const { return _options; }

        /**
         * \brief Gets the value of a flag.
         * 
         * \param tcp_flag The polled flag.
         * \return The value of the flag.
         */
        small_uint<1> get_flag(Flags tcp_flag);
        
        /* Setters */

        /**
         * \brief Setter for the destination port field.
         *
         * \param new_dport The new destination port.
         */
        void dport(uint16_t new_dport);

        /**
         * \brief Setter for the source port field.
         *
         * \param new_sport The new source port.
         */
        void sport(uint16_t new_sport);

        /**
         * \brief Setter for the sequence number.
         *
         * \param new_seq The new sequence number.
         */
        void seq(uint32_t new_seq);

        /**
         * \brief Setter for the acknowledge number.
         *
         * \param new_ack_seq The new acknowledge number.
         */
        void ack_seq(uint32_t new_ack_seq);

        /**
         * \brief Setter for the window size.
         *
         * \param new_window The new window size.
         */
        void window(uint16_t new_window);

        /**
         * \brief Setter for the checksum field.
         *
         * \param new_check The new checksum.
         */
        void check(uint16_t new_check);

        /**
         * \brief Setter for the urgent pointer field.
         *
         * \param new_urg_ptr The new urgent pointer.
         */
        void urg_ptr(uint16_t new_urg_ptr);

        /**
         * \brief Setter for the data offset pointer field.
         *
         * \param new_doff The new data offset pointer.
         */
        void data_offset(small_uint<4> new_doff);

        // Options

        /**
         * \brief Add a maximum segment size option.
         *
         * \param value The new maximum segment size.
         */
        void mss(uint16_t value);

        /**
         * \brief Searchs for a maximum segment size option.
         * \param value A pointer in which the option's value will be stored.
         * \return True if the option was found, false otherwise.
         */
        uint16_t mss() const;

        /**
         * \brief Add a window scale option.
         *
         * \param value The new window scale.
         */
        void winscale(uint8_t value);
        
        /**
         * \brief Searchs for a window scale option.
         * \param value A pointer in which the option's value will be stored.
         * \return True if the option was found, false otherwise.
         */
        uint8_t winscale() const;

        /**
         * \brief Add a sack permitted option.
         */
        void sack_permitted();
        
        /**
         * \brief Searchs for a sack permitted option.
         * \return True if the option was found, false otherwise.
         */
        bool has_sack_permitted() const;
        
        /**
         * \brief Add a sack option.
         *
         * \param value The new window scale.
         */
        void sack(const sack_type &edges);
        
        /**
         * \brief Searchs for a sack option.
         * \param value A pointer in which the option's value will be stored.
         * \return True if the option was found, false otherwise.
         */
        sack_type sack() const;

        /**
         * \brief Add a timestamp option.
         *
         * \param value The current value of the timestamp clock.
         * \param reply The echo reply field.
         */
        void timestamp(uint32_t value, uint32_t reply);

        /**
         * \brief Searchs for a timestamp option.
         * \param value A pointer in which the option's value will be stored.
         * \param reply A pointer in which the option's reply value will be stored.
         * \return True if the option was found, false otherwise.
         */
        std::pair<uint32_t, uint32_t> timestamp() const;

        /**
         * \brief Add a alternate checksum option.
         *
         * \param value The new alternate checksum scale.
         */
        void altchecksum(AltChecksums value);
        
        /**
         * \brief Searchs for a alternate checksum option.
         * \param value A pointer in which the option's value will be stored.
         * \return True if the option was found, false otherwise.
         */
        AltChecksums altchecksum() const;

        /**
         * \brief Set a TCP flag value.
         *
         * \param tcp_flag The flag to be set.
         * \param value The new value for this flag. Must be 0 or 1.
         */
        void set_flag(Flags tcp_flag, small_uint<1> value);

        /**
         * \brief Adds a TCP option.
         *
         * \param tcp_option The option type flag to be set.
         * \param length The length of this option(optional).
         * \param data Pointer to this option's data(optional).
         */
        void add_option(Option tcp_option, uint8_t length = 0, const uint8_t *data = 0);

        /**
         * \brief Returns the header size.
         *
         * This metod overrides PDU::header_size. This size includes the
         * payload and options size.
         *
         * \sa PDU::header_size
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         *
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::TCP; }

        /**
         * \brief Searchs for an option that matchs the given flag.
         * \param opt_flag The flag to be searched.
         * \return A pointer to the option, or 0 if it was not found.
         */
        const TCPOption *search_option(Option opt) const;
        
        /**
         * \sa PDU::clone_pdu
         */
        TCP *clone_pdu() const {
            return new TCP(*this);
        }
    private:
        struct tcphdr {
            uint16_t sport;
            uint16_t dport;
            uint32_t seq;
            uint32_t ack_seq;
        #if TINS_IS_LITTLE_ENDIAN
            uint16_t res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
        #elif TINS_IS_BIG_ENDIAN
            uint16_t doff:4,
                res1:4,
                cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
        #else
        #error	"Endian is not LE nor BE..."
        #endif
            uint16_t	window;
            uint16_t	check;
            uint16_t	urg_ptr;
        } __attribute__((packed));

        static const uint16_t DEFAULT_WINDOW;
        
        template<class T> 
        T generic_search(Option opt) const {
            const TCPOption *option = search_option(opt);
            if(option && option->data_size() == sizeof(T))
                return *(const T*)(&option->data_ptr()[0]);
            throw OptionNotFound();
        }
        /** \brief Serialices this TCP PDU.
         * \param buffer The buffer in which the PDU will be serialized.
         * \param total_sz The size available in the buffer.
         * \param parent The PDU that's one level below this one on the stack.
         */
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        tcphdr _tcp;
        options_type _options;
        uint32_t _options_size, _total_options_size;
    };
};

#endif // TINS_TCP_H
