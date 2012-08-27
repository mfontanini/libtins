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

#ifndef TINS_IP_H
#define TINS_IP_H

#ifndef WIN32
    #include <endian.h>
#endif
#include <string>
#include <utility>
#include <list>
#include "pdu.h"
#include "ipaddress.h"
#include "utils.h"

namespace Tins {

    /**
     * \brief Class that represents an IP PDU.
     * 
     * By default, IP PDUs are initialized, setting TTL to IP::DEFAULT_TTL,
     * id field to 1 and version to 4. Taking this into account, users
     * should set destination and source port and would be enough to send one.
     */
    class IP : public PDU {
    public:
        /**
         * his PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::IP;
    
        /**
         * The type used to store addresses.
         */
        typedef IPv4Address address_type;
    
        /**
         * \brief IP address size.
         */
        static const uint32_t ADDR_SIZE = 4;

        /**
         * \brief Enum indicating the option's class.
         *
         * Enum OptionClass represents the different classes of
         * IP Options.
         */
        enum OptionClass {
            CONTROL = 0,
            MEASUREMENT = 2
        };

        /**
         * \brief Enum indicating the option's id number.
         *
         * Enum Option indicates the possible IP Options.
         */
        enum Option {
            END = 0,
            NOOP = 1,
            SEC = 2,
            LSSR = 3,
            TIMESTAMP = 4,
            EXTSEC = 5,
            RR = 7,
            SID = 8,
            SSRR = 9,
            MTUPROBE = 11,
            MTUREPLY = 12,
            EIP = 17,
            TR = 18,
            ADDEXT = 19,
            RTRALT = 20,
            SDB = 21,
            DPS = 23,
            UMP = 24,
            QS = 25
        };
        
        /**
         * \brief This class represents an IP option. 
         */
        struct IPOption {
            friend class IP;
            struct {
            #if __BYTE_ORDER == __LITTLE_ENDIAN
                unsigned int number:5;
                unsigned int op_class:2;
                unsigned int copied:1;
            #elif __BYTE_ORDER == __BIG_ENDIAN
                unsigned int copied:1;
                unsigned int op_class:2;
                unsigned int number:5;
            #endif
            } __attribute__((__packed__)) type;
            
            uint8_t* write(uint8_t* buffer);
            
            /**
             * Getter for IP options' data pointer.
             */
            const uint8_t* data_ptr() const;
            
            /**
             * Getter for the data size field
             */
            uint8_t data_size() const;
        private:
            std::vector<uint8_t> optional_data;
        };

        /**
         * \brief Constructor for building the IP PDU.
         *
         * Both the destination and source IP address can be supplied.
         * By default, those fields are initialized using the IP 
         * address 0.0.0.0.
         *
         * \param ip_dst The destination ip address(optional).
         * \param ip_src The source ip address(optional).
         * \param child pointer to a PDU which will be set as the inner_pdu 
         * for the packet being constructed(optional).
         */
        IP(address_type ip_dst = address_type(), 
            address_type ip_src = address_type(), 
            PDU *child = 0);

        /**
         * \brief Constructor which creates an IP object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        IP(const uint8_t *buffer, uint32_t total_sz);

        /* Getters */

        /**
         * \brief Getter for the header length field.
         *
         * \return The number of dwords the header occupies in an uin8_t.
         */
        uint8_t head_len() const { return this->_ip.ihl; }

        /**
         * \brief Getter for the type of service field.
         *
         * \return The this IP PDU's type of service.
         */
        uint8_t tos() const { return _ip.tos; }

        /**
         * \brief Getter for the total length field.
         *
         * \return The total length of this IP PDU.
         */
        uint16_t tot_len() const { return Utils::be_to_host(_ip.tot_len); }

        /**
         * \brief Getter for the id field.
         *
         * \return The id for this IP PDU.
         */
        uint16_t id() const { return Utils::be_to_host(_ip.id); }

        /**
         * \brief Getter for the fragment offset field.
         *
         * \return The fragment offset for this IP PDU.
         */
        uint16_t frag_off() const { return Utils::be_to_host(_ip.frag_off); }

        /**
         * \brief Getter for the time to live field.
         *
         * \return The time to live for this IP PDU.
         */
        uint8_t ttl() const { return _ip.ttl; }

        /**
         * \brief Getter for the protocol field.
         *
         * \return The protocol for this IP PDU.
         */
        uint8_t protocol() const { return _ip.protocol; }

        /**
         * \brief Getter for the checksum field.
         *
         * \return The checksum for this IP PDU.
         */
        uint16_t check() const { return Utils::be_to_host(_ip.check); }

        /**
         * \brief Getter for the source address field.
         *
         * \return The source address for this IP PDU.
         */
        address_type src_addr() const { return address_type(_ip.saddr); }

        /** 
         * \brief Getter for the destination address field.
         * \return The destination address for this IP PDU.
         */
        address_type dst_addr() const  { return address_type(_ip.daddr); }
        
        /** 
         * \brief Getter for the version field.
         * \return The version for this IP PDU.
         */
        uint8_t version() const  { return _ip.version; }

        /* Setters */

        /**
         * \brief Setter for the header length field.
         *
         * \param new_head_len uint8_t with the new header length.
         */
        void head_len(uint8_t new_head_len);

        /**
         * \brief Setter for the type of service field.
         *
         * \param new_tos The new type of service.
         */
        void tos(uint8_t new_tos);

        /**
         * \brief Setter for the total length field.
         *
         * \param new_tot_len The new total length.
         */
        void tot_len(uint16_t new_tot_len);

        /**
         * \brief Setter for the id field.
         *
         * \param new_id The new id.
         */
        void id(uint16_t new_id);

        /**
         * \brief Setter for the fragment offset field.
         *
         * \param new_frag_off The new fragment offset.
         */
        void frag_off(uint16_t new_frag_off);

        /**
         * \brief Setter for the time to live field.
         *
         * \param new_ttl The new time to live.
         */
        void ttl(uint8_t new_ttl);

        /**
         * \brief Setter for the protocol field.
         *
         * \param new_protocol The new protocol.
         */
        void protocol(uint8_t new_protocol);

        /**
         * \brief Setter for the checksum field.
         *
         * \param new_check The new checksum.
         */
        void check(uint16_t new_check);

        /**
         * \brief Setter for the source address field.
         *
         * \param ip The source address to be set.
         */
        void src_addr(address_type ip);

        /**
         * \brief Setter for the destination address field.
         *
         * \param ip The destination address to be set.
         */
        void dst_addr(address_type ip);
        
        /**
         * \brief Setter for the version field.
         *
         * \param ver The version field to be set.
         */
        void version(uint8_t ver);

        /**
         * \brief Sets an IP option.
         *
         * \param copied The copied flag for this option.
         * \param op_class The option class to be set.
         * \param number The options number to be set.
         * \param data The data of this options.
         * \param data_size The data size.
         */
        void set_option(uint8_t copied, OptionClass op_class, Option number, const uint8_t* data = 0, uint32_t data_size = 0);

        /**
         * \brief Searchs for an option that matchs the given flag.
         * \param opt_class The option class to be searched.
         * \param opt_number The option number to be searched.
         * \return A pointer to the option, or 0 if it was not found.
         */
        const IPOption *search_option(OptionClass opt_class, Option opt_number) const;

        /**
         * \brief Sets the End of List option.
         */
        void set_eol_option();

        /**
         * \brief Sets the NOP option.
         */
        void set_noop_option();

        /**
         * \brief Sets the security option.
         *
         * \param data The data for this option
         * \param data_len The length of the data.
         */
        void set_sec_option(const uint8_t* data, uint32_t data_len);
        /* Add more option setters */

        /* Virtual methods */

        /**
         * \brief Returns the header size.
         *
         * This metod overrides PDU::header_size. \sa PDU::header_size
         */
        uint32_t header_size() const;

        /**
         * \sa PDU::send()
         */
        bool send(PacketSender* sender);

        /**
         * \brief Check wether ptr points to a valid response for this PDU.
         *
         * \sa PDU::matches_response
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        bool matches_response(uint8_t *ptr, uint32_t total_sz);

        /**
         * \brief Receives a matching response for this packet.
         *
         * \sa PDU::recv_response
         * \param sender The packet sender which will receive the packet.
         */
        PDU *recv_response(PacketSender *sender);

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::IP; }

        /**
         * \brief Clones this pdu, filling the corresponding header with data
         * extracted from a buffer.
         *
         * \param ptr The pointer to the from from which the data will be extracted.
         * \param total_sz The size of the buffer.
         * \return The cloned PDU.
         * \sa PDU::clone_packet
         */
        PDU *clone_packet(const uint8_t *ptr, uint32_t total_sz);

        /**
         * \sa PDU::clone_pdu
         */
        PDU *clone_pdu() const {
            return do_clone_pdu<IP>();
        }
    private:
        static const uint8_t DEFAULT_TTL;

        struct iphdr {
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            unsigned int ihl:4;
            unsigned int version:4;
        #elif __BYTE_ORDER == __BIG_ENDIAN
            unsigned int version:4;
            unsigned int ihl:4;
        #else
        # error "Endian is not LE nor BE..."
        #endif
            uint8_t tos;
            uint16_t tot_len;
            uint16_t id;
            uint16_t frag_off;
            uint8_t ttl;
            uint8_t protocol;
            uint16_t check;
            uint32_t saddr;
            uint32_t daddr;
            /*The options start here. */
        } __attribute__((__packed__));

        void init_ip_fields();
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        iphdr _ip;
        std::list<IPOption> _ip_options;
        uint32_t _options_size, _padded_options_size;
    };
};

#endif // TINS_IP_H
