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

#ifndef TINS_TCP_H
#define TINS_TCP_H


#include <list>
#include <vector>
#include <stdint.h>
#include <stdexcept>
#include <utility>
#include "pdu.h"
#include "macros.h"
#include "endianness.h"
#include "small_uint.h"
#include "pdu_option.h"
#include "cxxstd.h"

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
        enum OptionTypes {
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
         * The type used to store TCP options.
         */
        typedef PDUOption<uint8_t> option;

        /**
         * The type used to store the options.
         */
        typedef std::list<option> options_type;
        
        /**
         * The type used to store the sack option.
         */
        typedef std::vector<uint32_t> sack_type;

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
         * \brief Constructs TCP object from a buffer.
         * 
         * If there is not enough size for a TCP header, or any of the
         * TLV options are malformed a malformed_packet exception is 
         * thrown.
         * 
         * Any extra data will be stored in a RawPDU.
         * 
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
         * \param option The option to be added.
         */
        void add_option(const option &opt);
        
        #if TINS_IS_CXX11
            /**
             * \brief Adds a TCP option.
             *
             * This move-constructs the option.
             * 
             * \param option The option to be added.
             */
            void add_option(option &&opt);
        #endif

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
         * \brief Check wether ptr points to a valid response for this PDU.
         *
         * \sa PDU::matches_response
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        bool matches_response(uint8_t *ptr, uint32_t total_sz);

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
        const option *search_option(OptionTypes opt) const;
        
        /**
         * \sa PDU::clone
         */
        TCP *clone() const {
            return new TCP(*this);
        }
    private:
        TINS_BEGIN_PACK
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
        } TINS_END_PACK;

        static const uint16_t DEFAULT_WINDOW;
        
        template<class T> 
        T generic_search(OptionTypes opt) const {
            const option *option = search_option(opt);
            if(option && option->data_size() == sizeof(T))
                return *(const T*)(&option->data_ptr()[0]);
            throw option_not_found();
        }
        
        void internal_add_option(const option &option);
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        uint8_t *write_option(const option &opt, uint8_t *buffer);

        tcphdr _tcp;
        uint16_t _options_size, _total_options_size;
        options_type _options;
    };
}

#endif // TINS_TCP_H
