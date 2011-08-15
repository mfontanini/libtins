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
         * \brief Constructor for building the IP PDU taking strings.
         *
         * Constructor that builds an IP using strings as addresses. They
         * can be hostnames or IPs.
         *
         * \param ip_dst string containing the destination hostname(optional).
         * \param ip_src string containing the source hostname(optional).
         * \param child pointer to a PDU which will be set as the inner_pdu for the packet being constructed(optional).
         */
        IP(const std::string &ip_dst = "", const std::string &ip_src = "", PDU *child = 0);
        IP(uint32_t ip_dst = 0, uint32_t ip_src = 0, PDU *child = 0);

        inline uint8_t tos() const { return _ip.tos; }
        inline uint16_t tot_len() const { return _ip.tot_len; }
        inline uint16_t id() const { return _ip.id; }
        inline uint16_t frag_off() const { return _ip.frag_off; }
        inline uint8_t ttl() const { return _ip.ttl; }
        inline uint8_t protocol() const { return _ip.protocol; }
        inline uint16_t check() const { return _ip.check; }
        inline uint32_t source_address() const { return _ip.saddr; }
        inline uint32_t dest_address() const  { return _ip.daddr; }

        void tos(uint8_t new_tos);
        void tot_len(uint16_t new_tot_len);
        void id(uint16_t new_id);
        void frag_off(uint16_t new_frag_off);
        void ttl(uint8_t new_ttl);
        void protocol(uint8_t new_protocol);
        void check(uint16_t new_check);
        void source_address(const std::string &ip);
        void source_address(uint32_t ip);
        void dest_address(const std::string &ip);
        void dest_address(uint32_t ip);
        void set_option(uint8_t copied, OptionClass op_class, OptionNumber number, uint8_t* data = 0, uint32_t data_size = 0);

        void set_option_eol();
        void set_option_noop();
        void set_option_sec(uint8_t* data, uint32_t data_len);
        /* Add more option setters */

        /* Virtual methods */
        uint32_t header_size() const;
        bool send(PacketSender* sender);

        bool matches_response(uint8_t *ptr, uint32_t total_sz);

        PDU *recv_response(PacketSender *sender);

        PDUType pdu_type() const { return PDU::IP; }

        PDU *clone_packet(uint8_t *ptr, uint32_t total_sz);
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
