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

#ifndef __ETHERNET_H
#define __ETHERNET_H

#include <stdint.h>

#include "pdu.h"

namespace Tins {

    /**
     * \brief Class representing an ethernet IEEE 802.3 packet
     */
    class Ethernet : public PDU {

    public:
        /**
         * \brief Constructor for creating an ethernet PDU
         *
         * Constructor that builds an ethernet PDU taking the destination's
         * and source's MAC.
         *
         * \param mac_dst uint8_t array of 6 bytes containing the destination's MAC.
         * \param mac_src uint8_t array of 6 bytes containing the source's MAC.
         */
        Ethernet(const uint8_t mac_dst[6], const uint8_t mac_src[6], PDU* child = 0);

        /* Getters */
        /**
         * \brief Getter for the destination's mac address.
         *
         * \return Returns the destination's mac address as a constant uint8_t pointer.
         */
        inline const uint8_t* dst_mac() const { return this->header.dst_mac; }

        /**
         * \brief Getter for the source's mac address.
         *
         * \return Returns the source's mac address as a constant uint8_t pointer.
         */
        inline const uint8_t* src_mac() const { return this->header.src_mac; }

        /**
         * \brief Getter for the CRC value.
         *
         * \return Returns the CRC.
         */
        inline uint32_t crc() const { return this->_crc; }

        /* Setters */
        /**
         * \brief Setter for the destination's MAC.
         *
         * \param new_dst_mac uint8_t array of 6 bytes containing the new destination's MAC.
         */
        void dst_mac(uint8_t new_dst_mac[6]);

        /**
         * \brief Setter for the source's MAC.
         *
         * \param new_src_mac uint8_t array of 6 bytes containing the new source's MAC.
         */
        void src_mac(uint8_t new_src_mac[6]);

        /**
         * \brief Setter for the CRC value.
         *
         * \param new_crc uint32_t containing the new CRC value.
         */
        void crc(uint32_t new_crc);

        /* Virtual methods */
        /**
         * \brief Returns the ethernet frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Returns the ethernet frame's trailer length.
         *
         * \return An uint32_t with the trailer's size.
         * \sa PDU::trailer_size()
         */
        uint32_t trailer_size() const;

        /**
         * \sa PDU::send()
         */
        bool send(PacketSender* sender);

    private:
        /**
         * Struct that represents the IEEE 802.3 header
         */
        struct ethernet_header {
            uint8_t dst_mac[6];
            uint8_t src_mac[6];
            uint16_t payload_type;
        };

        ethernet_header header;
        uint32_t _crc;

        void write_serialization(uint8_t *buffer, uint32_t total_sz, PDU *parent);

    };

};

#endif
