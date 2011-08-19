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

#ifndef __IP_H
#define __IP_H

#ifndef WIN32
    #include <endian.h>
#endif
#include <string>
#include <utility>
#include <vector>
#include "pdu.h"
#include "utils.h"

namespace Tins {

    /**
     * \brief IP represents IP PDU.
     */
    class IP : public PDU {
    public:
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
         * Enum OptionNumber indicates the possible IP Options.
         */
        enum OptionNumber {
            IPOPT_END = 0,
            IPOPT_NOOP = 1,
            IPOPT_SEC = 2,
            IPOPT_LSSR = 3,
            IPOPT_TIMESTAMP = 4,
            IPOPT_EXTSEC = 5,
            IPOPT_RR = 7,
            IPOPT_SID = 8,
            IPOPT_SSRR = 9,
            IPOPT_MTUPROBE = 11,
            IPOPT_MTUREPLY = 12,
            IPOPT_EIP = 17,
            IPOPT_TR = 18,
            IPOPT_ADDEXT = 19,
            IPOPT_RTRALT = 20,
            IPOPT_SDB = 21,
            IPOPT_DPS = 23,
            IPOPT_UMP = 24,
            IPOPT_QS = 25
        };

        /**
         * \brief Constructor for building the IP PDU taking strings as ip addresses.
         *
         * Constructor that builds an IP using strings as addresses. They
         * can be hostnames or IPs.
         *
         * \param ip_dst string containing the destination hostname(optional).
         * \param ip_src string containing the source hostname(optional).
         * \param child pointer to a PDU which will be set as the inner_pdu for the packet being constructed(optional).
         */
        IP(const std::string &ip_dst = "", const std::string &ip_src = "", PDU *child = 0);

        /**
         * \brief Constructor for building the IP PDU taking integer as ip addresses.
         *
         * Constructor that builds an IP using strings as addresses. They
         * can be hostnames or IPs.
         *
         * \param ip_dst The destination ip address(optional).
         * \param ip_src The source ip address(optional).
         * \param child pointer to a PDU which will be set as the inner_pdu for the packet being constructed(optional).
         */
        IP(uint32_t ip_dst = 0, uint32_t ip_src = 0, PDU *child = 0);

        /**
         * \brief Constructor which creates an IP object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        IP(const uint8_t *buffer, uint32_t total_sz);
        
        /**
         * \brief Destructor for IP objects.
         *
         * Destructs IP objects releasing the allocated memory for the options
         * if options exist.
         */
        ~IP();

        /* Getters */

        /**
         * \brief Getter for the header length field.
         *
         * \return The number of dwords the header occupies in an uin8_t.
         */
        inline uint8_t head_len() const { return this->_ip.ihl; }

        /**
         * \brief Getter for the type of service field.
         *
         * \return The this IP PDU's type of service.
         */
        inline uint8_t tos() const { return _ip.tos; }

        /**
         * \brief Getter for the total length field.
         *
         * \return The total length of this IP PDU.
         */
        inline uint16_t tot_len() const { return Utils::net_to_host_s(_ip.tot_len); }

        /**
         * \brief Getter for the id field.
         *
         * \return The id for this IP PDU.
         */
        inline uint16_t id() const { return Utils::net_to_host_s(_ip.id); }

        /**
         * \brief Getter for the fragment offset field.
         *
         * \return The fragment offset for this IP PDU.
         */
        inline uint16_t frag_off() const { return Utils::net_to_host_s(_ip.frag_off); }

        /**
         * \brief Getter for the time to live field.
         *
         * \return The time to live for this IP PDU.
         */
        inline uint8_t ttl() const { return _ip.ttl; }

        /**
         * \brief Getter for the protocol field.
         *
         * \return The protocol for this IP PDU.
         */
        inline uint8_t protocol() const { return _ip.protocol; }

        /**
         * \brief Getter for the checksum field.
         *
         * \return The checksum for this IP PDU.
         */
        inline uint16_t check() const { return Utils::net_to_host_s(_ip.check); }

        /**
         * \brief Getter for the source address field.
         *
         * \return The source address for this IP PDU.
         */
        inline uint32_t src_addr() const { return _ip.saddr; }

        /** \brief Getter for the destination address field.
         * \return The destination address for this IP PDU.
         */
        inline uint32_t dst_addr() const  { return _ip.daddr; }

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
         * \param ip The ip address in dotted string notation.
         */
        void src_addr(const std::string &ip);

        /**
         * \brief Setter for the source address field.
         *
         * \param ip The ip address in integer notation.
         */
        void src_addr(uint32_t ip);

        /**
         * \brief Setter for the destination address field.
         *
         * \param ip The ip address in dotted string notation.
         */
        void dst_addr(const std::string &ip);

        /**
         * \brief Setter for the destination address field.
         *
         * \param ip The ip address in integer notation.
         */
        void dst_addr(uint32_t ip);

        /**
         * \brief Sets an IP option.
         *
         * \param copied The copied flag for this option.
         * \param op_class The option class to be set.
         * \param number The options number to be set.
         * \param data The data of this options.
         * \param data_size The data size.
         */
        void set_option(uint8_t copied, OptionClass op_class, OptionNumber number, uint8_t* data = 0, uint32_t data_size = 0);

        /**
         * \brief Sets the End of List option.
         */
        void set_option_eol();

        /**
         * \brief Sets the NOP option.
         */
        void set_option_noop();

        /**
         * \brief Sets the security option.
         *
         * \param data The data for this option
         * \param data_len The length of the data.
         */
        void set_option_sec(uint8_t* data, uint32_t data_len);
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

        struct IpOption {
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
            } type;
            uint8_t* optional_data;
            uint32_t optional_data_size;

            uint8_t* write(uint8_t* buffer);

        } __attribute__((__packed__));

        /** \brief Creates an instance of IP from an iphdr pointer.
         *
         * \param ptr The ip header pointer.
         */
        IP(const iphdr *ptr);

        void init_ip_fields();
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        iphdr _ip;
        std::vector<IpOption> _ip_options;
        uint32_t _options_size, _padded_options_size;
    };
};

#endif
