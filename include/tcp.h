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
#ifndef WIN32
    #include <endian.h>
#endif
#include "pdu.h"
#include "utils.h"


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
         * \brief This PDU's flag.
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
        struct TCPOption {
            /**
             * \brief Creates an instance of a TCPOption.
             * \param okind The option kind.
             * \param olength The option's data length.
             * \param odata The option's data(if any).
             */
            TCPOption(uint8_t opt = 0, uint8_t length = 0, const uint8_t *value = 0) 
            : option(opt), value(value, (value) ? (value + length) : 0) { 
                
            }

            /**
             * \brief Writes the option into a buffer.
             * \param buffer The buffer in which to write the option.
             * \return The buffer pointer incremented by the size of this option.
             */
            uint8_t *write(uint8_t *buffer);
            
            uint8_t option;
            std::vector<uint8_t> value;
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
        inline uint16_t dport() const { return Utils::net_to_host_s(_tcp.dport); }

        /**
         * \brief Getter for the source port field.
         *
         * \return The source port in an uint16_t.
         */
        inline uint16_t sport() const { return Utils::net_to_host_s(_tcp.sport); }

        /**
         * \brief Getter for the sequence number field.
         *
         * \return The sequence number in an uint32_t.
         */
        inline uint32_t seq() const { return Utils::net_to_host_l(_tcp.seq); }

        /**
         * \brief Getter for the acknowledge number field.
         *
         * \return The acknowledge number in an uint32_t.
         */
        inline uint32_t ack_seq() const { return Utils::net_to_host_l(_tcp.ack_seq); }

        /**
         * \brief Getter for the window size field.
         *
         * \return The window size in an uint32_t.
         */
        inline uint16_t window() const { return Utils::net_to_host_s(_tcp.window); }

        /**
         * \brief Getter for the checksum field.
         *
         * \return The checksum field in an uint16_t.
         */
        inline uint16_t check() const { return Utils::net_to_host_s(_tcp.check); }

        /**
         * \brief Getter for the urgent pointer field.
         *
         * \return The urgent pointer in an uint16_t.
         */
        inline uint16_t urg_ptr() const { return Utils::net_to_host_s(_tcp.urg_ptr); }

        /**
         * \brief Getter for the data offset field.
         *
         * \return Data offset in an uint8_t.
         */
        inline uint8_t data_offset() const { return this->_tcp.doff; }

        /**
         * \brief Getter for the option list.
         * 
         * \return The options list.
         */
        inline const std::list<TCPOption> &options() const { return _options; }

        /**
         * \brief Gets the value of a flag.
         * 
         * \param tcp_flag The polled flag.
         * \return The value of the flag.
         */
        uint8_t get_flag(Flags tcp_flag);
        
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
        void data_offset(uint8_t new_doff);

        /**
         * \brief Set the payload.
         *
         * Payload is NOT copied. Therefore, pointers provided as
         * payloads must be freed manually by the user. This actually
         * creates a RawPDU that holds the payload, and sets it as the
         * inner_pdu. Therefore, if an inner_pdu was set previously,
         * a call to TCP::payload will delete it.
         *
         * \param new_payload New payload.
         * \param new_payload_size New payload's size
         */
        void payload(uint8_t *new_payload, uint32_t new_payload_size);

        /**
         * \brief Add a maximum segment size option.
         *
         * \param value The new maximum segment size.
         */
        void add_mss_option(uint16_t value);

        /**
         * \brief Searchs for a maximum segment size option.
         * \param value A pointer in which the option's value will be stored.
         * \return True if the option was found, false otherwise.
         */
        bool search_mss_option(uint16_t *value);

        /**
         * \brief Add a window scale option.
         *
         * \param value The new window scale.
         */
        void add_winscale_option(uint8_t value);
        
        /**
         * \brief Searchs for a window scale option.
         * \param value A pointer in which the option's value will be stored.
         * \return True if the option was found, false otherwise.
         */
        bool search_winscale_option(uint8_t *value);

        /**
         * \brief Add a sack permitted option.
         */
        void add_sack_permitted_option();
        
        /**
         * \brief Searchs for a sack permitted option.
         * \return True if the option was found, false otherwise.
         */
        bool search_sack_permitted_option();
        
        /**
         * \brief Add a sack option.
         *
         * \param value The new window scale.
         */
        void add_sack_option(const std::list<uint32_t> &edges);
        
        /**
         * \brief Searchs for a sack option.
         * \param value A pointer in which the option's value will be stored.
         * \return True if the option was found, false otherwise.
         */
        bool search_sack_option(std::list<uint32_t> *edges);

        /**
         * \brief Add a timestamp option.
         *
         * \param value The current value of the timestamp clock.
         * \param reply The echo reply field.
         */
        void add_timestamp_option(uint32_t value, uint32_t reply);

        /**
         * \brief Searchs for a timestamp option.
         * \param value A pointer in which the option's value will be stored.
         * \param reply A pointer in which the option's reply value will be stored.
         * \return True if the option was found, false otherwise.
         */
        bool search_timestamp_option(uint32_t *value, uint32_t *reply);

        /**
         * \brief Add a alternate checksum option.
         *
         * \param value The new alternate checksum scale.
         */
        void add_altchecksum_option(AltChecksums value);
        
        /**
         * \brief Searchs for a alternate checksum option.
         * \param value A pointer in which the option's value will be stored.
         * \return True if the option was found, false otherwise.
         */
        bool search_altchecksum_option(uint8_t *value);

        /**
         * \brief Set a TCP flag value.
         *
         * \param tcp_flag The flag to be set.
         * \param value The new value for this flag. Must be 0 or 1.
         */
        void set_flag(Flags tcp_flag, uint8_t value);

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
        PDU *clone_pdu() const {
            return do_clone_pdu<TCP>();
        }
    private:
        struct tcphdr {
            uint16_t sport;
            uint16_t dport;
            uint32_t seq;
            uint32_t ack_seq;
        #if __BYTE_ORDER == __LITTLE_ENDIAN
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
        #elif __BYTE_ORDER == __BIG_ENDIAN
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
        
        template<class T> bool generic_search(Option opt, T *value) {
            const TCPOption *option = search_option(opt);
            if(option && option->value.size() == sizeof(T)) {
                *value = *(const T*)(&option->value[0]);
                return true;
            }
            return false;
        }
        /** \brief Serialices this TCP PDU.
         * \param buffer The buffer in which the PDU will be serialized.
         * \param total_sz The size available in the buffer.
         * \param parent The PDU that's one level below this one on the stack.
         */
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        tcphdr _tcp;
        std::list<TCPOption> _options;
        uint32_t _options_size, _total_options_size;
    };
};

#endif // TINS_TCP_H
