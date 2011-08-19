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

#ifndef __ETHERNET_II_H
#define __ETHERNET_II_H

#include <stdint.h>
#include <stdexcept>

#include "pdu.h"

namespace Tins {

    /**
     * \brief Class representing an Ethernet II packet
     */
    class EthernetII : public PDU {

    public:

        /** \brief Represents the ethernetII broadcast address.
         */
        static const uint8_t* BROADCAST;

        /**
         * \brief Constructor for creating an ethernet PDU
         *
         * Constructor that builds an ethernet PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the ethernet PDU (optional).
         */
        EthernetII(const std::string& iface, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an ethernet PDU
         *
         * Constructor that builds an ethernet PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the ethernet PDU (optional).
         */
        EthernetII(uint32_t iface_index, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor which creates an EthernetII object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        EthernetII(const uint8_t *buffer, uint32_t total_sz);
        
        /* Getters */
        /**
         * \brief Getter for the destination's mac address.
         *
         * \return Returns the destination's mac address as a constant uint8_t pointer.
         */
        inline const uint8_t* dst_hw_addr() const { return _eth.dst_mac; }

        /**
         * \brief Getter for the source's mac address.
         *
         * \return Returns the source's mac address as a constant uint8_t pointer.
         */
        inline const uint8_t* src_hw_addr() const { return _eth.src_mac; }

        /**
         * \brief Getter for the interface.
         *
         * \return Returns the interface's index as an uint32_t.
         */
        inline uint32_t iface() const { return this->_iface_index; }

        /**
         * \brief Getter for the payload_type
         * \return The payload type.
         */
        uint16_t payload_type() const;

        /* Setters */
        
        /**
         * \brief Setter for the destination's MAC.
         *
         * \param new_dst_mac uint8_t array of 6 bytes containing the new destination's MAC.
         */
        void dst_hw_addr(const uint8_t* new_dst_mac);

        /**
         * \brief Setter for the source's MAC.
         *
         * \param new_src_mac uint8_t array of 6 bytes containing the new source's MAC.
         */
        void src_hw_addr(const uint8_t* new_src_mac);

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

        /** \brief Check wether ptr points to a valid response for this PDU.
         *
         * \sa PDU::matches_response
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        bool matches_response(uint8_t *ptr, uint32_t total_sz);

        /** \brief Receives a matching response for this packet.
         *
         * \sa PDU::recv_response
         * \param sender The packet sender which will receive the packet.
         */
        PDU *recv_response(PacketSender *sender);

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::ETHERNET_II; }

        /** \brief Clones this pdu, filling the corresponding header with data
         * extracted from a buffer.
         *
         * \param ptr The pointer to the from from which the data will be extracted.
         * \param total_sz The size of the buffer.
         * \return The cloned PDU.
         * \sa PDU::clone_packet
         */
        PDU *clone_packet(uint8_t *ptr, uint32_t total_sz);
    private:
        /**
         * Struct that represents the Ethernet II header
         */
        struct ethhdr {
            uint8_t dst_mac[6];
            uint8_t src_mac[6];
            uint16_t payload_type;
        } __attribute__((__packed__));

        /** \brief Creates an instance of EthernetII using an ethhdr pointer.
         *
         * \param eth_ptr The pointer to the ethhdr.
         */
        EthernetII(ethhdr *eth_ptr);

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        

        ethhdr _eth;
        uint32_t _iface_index;
    };

};

#endif
