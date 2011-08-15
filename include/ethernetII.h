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
#include <stdexcept>

#include "pdu.h"

namespace Tins {

    /**
     * \brief Class representing an ethernet IEEE 802.3 packet
     */
    class EthernetII : public PDU {

    public:
        /**
         * \brief Constructor for creating an ethernet PDU
         *
         * Constructor that builds an ethernet PDU taking the destination's
         * and source's MAC.
         *
         * \param mac_dst uint8_t array of 6 bytes containing the destination's MAC.
         * \param mac_src uint8_t array of 6 bytes containing the source's MAC.
         * \param iface string containing the interface's name from where to send the packet.
         * \param child PDU* with the PDU contained by the ethernet PDU (optional).
         */
        EthernetII(const uint8_t* mac_dst, const uint8_t* mac_src, const std::string& iface, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an ethernet PDU
         *
         * Constructor that builds an ethernet PDU taking the destination's
         * and source's MAC.
         *
         * \param mac_dst uint8_t array of 6 bytes containing the destination's MAC.
         * \param mac_src uint8_t array of 6 bytes containing the source's MAC.
         * \param iface_index uint32_t containing the interface's index from where to send the packet.
         * \param child PDU* with the PDU contained by the ethernet PDU (optional).
         */
        EthernetII(const uint8_t* mac_dst, const uint8_t* mac_src, const uint32_t iface_index, PDU* child = 0);

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
         * \brief Getter for the interface.
         *
         * \return Returns the interface's index as an uint32_t.
         */
        inline uint32_t iface() const { return this->_iface_index; }

        /* Setters */
        /**
         * \brief Setter for the destination's MAC.
         *
         * \param new_dst_mac uint8_t array of 6 bytes containing the new destination's MAC.
         */
        void dst_mac(const uint8_t* new_dst_mac);

        /**
         * \brief Setter for the source's MAC.
         *
         * \param new_src_mac uint8_t array of 6 bytes containing the new source's MAC.
         */
        void src_mac(const uint8_t* new_src_mac);

        /**
         * \brief Setter for the interface.
         *
         * \param new_iface_index uint32_t containing the new interface index.
         */
        void iface(uint32_t new_iface_index);

        /**
         * \brief Setter for the interface.
         *
         * \param new_iface string reference containing the new interface name.
         */
        void iface(const std::string& new_iface) throw (std::runtime_error);

        /* Virtual methods */
        /**
         * \brief Returns the ethernet frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \sa PDU::send()
         */
        bool send(PacketSender* sender);

        PDUType pdu_type() const { return PDU::ETHERNET_II; }

    private:
        /**
         * Struct that represents the Ethernet II header
         */
        struct ethernet_header {
            uint8_t dst_mac[6];
            uint8_t src_mac[6];
            uint16_t payload_type;
        } __attribute__((__packed__));

        ethernet_header header;
        uint32_t _iface_index;

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

    };

};

#endif
