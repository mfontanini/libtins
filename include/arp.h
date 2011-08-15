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


#ifndef __ARP_H
#define __ARP_H


#include <string>
#include "pdu.h"

namespace Tins {

    /**
     * \brief Class that represents an ARP PDU.
     *
     */
    class ARP : public PDU {
    public:
        /**
         * \brief Enum which indicates the type of ARP packet.
         */
        enum Flags {
            REQUEST = 0x0100,
            REPLY   = 0x0200
        };

        /**
         * \brief Default constructor for ARP PDU objects.
         */
        ARP();

        /* Getters */
        /**
         * \brief Getter for the sender's hardware's address.
         *
         * \return The hardware address of the sender in an uint8_t*.
         */
        inline const uint8_t* sender_hw_address() { return this->_arp.ar_sha; }

        PDUType pdu_type() const { return PDU::ARP; }

        void set_arp_request(const std::string &ip_dst, const std::string &ip_src, const std::string &hw_src = "");

        uint32_t header_size() const;

    private:
        struct arphdr {
            uint16_t ar_hrd;	/* format of hardware address	*/
            uint16_t ar_pro;	/* format of protocol address	*/
            uint8_t	ar_hln;		/* length of hardware address	*/
            uint8_t	ar_pln;		/* length of protocol address	*/
            uint16_t ar_op;		/* ARP opcode (command)		*/

            uint8_t ar_sha[6];	/* sender hardware address	*/
            uint32_t ar_sip;	/* sender IP address		*/
            uint8_t ar_tha[6];	/* target hardware address	*/
            uint32_t ar_tip;	/* target IP address		*/
        } __attribute__((__packed__));

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        arphdr _arp;
    };
};
#endif
