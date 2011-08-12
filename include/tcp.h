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

#ifndef __TCP_H
#define __TCP_H


#include <vector>
#include <stdint.h>
#ifndef WIN32
    #include <endian.h>
#endif
#include "pdu.h"


namespace Tins {

    /** \brief TCP represents the TCP PDU.
     * 
     * TCP is the representation of the TCP PDU. Instances of this class
     * must be sent over a level 3 PDU, this will otherwise fail.
     */

    class TCP : public PDU {
    public:
        /** \brief TCP flags enum.
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
        
        /** \brief TCP options enum.
         * 
         * This enum identifies valid options supported by TCP PDU.
         */
        
        enum Options {
            MSS = 2,
            TSOPT = 8
        };
    
        /** \brief TCP constructor.
         * 
         * Creates an instance of TCP. Destination and source port can
         * be provided, otherwise both will be 0.
         * \param dport Destination port.
         * \param sport Source port.
         * */
    
        TCP(uint16_t dport = 0, uint16_t sport = 0);
        
        /** \brief TCP destructor.
         * 
         * Destructs the TCP instance. Does not free the payload.
         * */
        
        ~TCP();
        
        /** \brief Returns the destination port.
         */
        inline uint16_t dport() const { return _tcp.dport; }
        
        /** \brief Returns the source port.
         */
        inline uint16_t sport() const { return _tcp.sport; }
        
        /** \brief Returns the sequence number.
         */
        inline uint32_t seq() const { return _tcp.seq; }
        
        /** \brief Returns the acknowledge number.
         */
        inline uint32_t ack_seq() const { return _tcp.ack_seq; }
        
        /** \brief Returns the window size.
         */
        inline uint16_t window() const { return _tcp.window; }
        
        /** \brief Returns the checksum.
         */
        inline uint16_t check() const { return _tcp.check; }
        
        /** \brief Returns the urgent pointer.
         */
        inline uint16_t urg_ptr() const { return _tcp.urg_ptr; }
        
        /** \brief Set the destination port.
         * \param new_dport New destination port.
         */
        void dport(uint16_t new_dport);
        
        /** \brief Set the source port.
         * \param new_dport New source port.
         */
        void sport(uint16_t new_sport);
        
        /** \brief Set the sequence number.
         * \param new_seq New sequence number.
         */
        void seq(uint32_t new_seq);
        
        /** \brief Set the acknowledge number.
         * \param new_ack_seq New acknowledge number.
         */
        void ack_seq(uint32_t new_ack_seq);
        
        /** \brief Set the window size.
         * \param new_window New window size.
         */
        void window(uint16_t new_window);
        
        /** \brief Set the checksum.
         * \param new_check New checksum.
         */
        void check(uint16_t new_check);
        
        /** \brief Set the urgent pointer.
         * \param new_urg_ptr New urgent pointer.
         */
        void urg_ptr(uint16_t new_urg_ptr);
        
        /** \brief Set the payload.
         * 
         * Payload is NOT copied. Therefore, pointers provided as 
         * payloads must be freed manually by the user.
         * \param new_payload New payload.
         */
        void payload(uint8_t *new_payload, uint32_t new_payload_size);
        
        /** \brief Set maximum segment size.
         * \param value New maximum segment size.
         */
        void set_mss(uint16_t value);
        
        /** \brief Set the timestamp.
         * \param value Current value of the timestamp clock.
         * \param reply Echo reply field.
         */
        void set_timestamp(uint32_t value, uint32_t reply);
        
        /** \brief Set a TCP flag value.
         * \param tcp_flag Indicates which flag will be set.
         * \param value New value for this flag. Must be 0 or 1.
         */
        void set_flag(Flags tcp_flag, uint8_t value);
        
        /** \brief Adds a TCP option.
         * \param tcp_option Indicates the option that will be set.
         * \param length Length of this option.
         * \param data This option's data.
         */
        void add_option(Options tcp_option, uint8_t length = 0, uint8_t *data = 0);
        
        /* Virtual methods */
        /** \brief Returns the header size.
         * 
         * This metod overrides PDU::header_size. This size includes the
         * payload and options size.
         */
        uint32_t header_size() const;
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
        
        struct TCPOption {
            TCPOption(uint8_t okind, uint8_t olength, uint8_t *odata) :
                      kind(okind), length(olength), data(odata) { } 
            
            uint8_t *write(uint8_t *buffer);
            
            uint8_t kind, length;
            uint8_t *data;
        };
        
        static const uint16_t DEFAULT_WINDOW;
        
        /** \brief Serialices this TCP PDU.
         * \param buffer The buffer in which the PDU will be serialized.
         * \param total_sz The size available in the buffer.
         * \param parent The PDU that's one level below this one on the stack.
         */
        void write_serialization(uint8_t *buffer, uint32_t total_sz, PDU *parent);
        
        uint32_t do_checksum(uint8_t *start, uint8_t *end) const;
        uint32_t pseudoheader_checksum(uint32_t source_ip, uint32_t dest_ip) const;
        
        tcphdr _tcp;
        std::vector<TCPOption> _options;
        uint8_t *_payload;
        uint32_t _payload_size, _options_size, _total_options_size;
    };
};

#endif
