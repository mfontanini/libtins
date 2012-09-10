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

#ifndef TINS_IEEE802_3_H
#define TINS_IEEE802_3_H

#include <stdint.h>

#include "pdu.h"
#include "endianness.h"
#include "hw_address.h"
#include "network_interface.h"

namespace Tins {

    /** 
     * \brief Class representing an Ethernet II PDU.
     */
    class IEEE802_3 : public PDU {
    public:
        /**
         * \brief The address type.
         */
        typedef HWAddress<6> address_type; 
        
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::IEEE802_3;

        /**
         * \brief Represents the IEEE802_3 broadcast address.
         */
        static const address_type BROADCAST;

        /**
         * \brief Constructor for creating an IEEE802_3 PDU
         *
         * Constructor that builds an IEEE802_3 PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the ethernet PDU (optional).
         */
        IEEE802_3(const NetworkInterface& iface, 
                  const address_type &dst_hw_addr = address_type(), 
                  const address_type &src_hw_addr = address_type(), 
                  PDU* child = 0);

        /**
         * \brief Constructor which creates an IEEE802_3 object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        IEEE802_3(const uint8_t *buffer, uint32_t total_sz);

        /* Getters */
        /**
         * \brief Getter for the destination's mac address.
         *
         * \return Returns the destination's mac address as a constant uint8_t pointer.
         */
        address_type dst_addr() const { return _eth.dst_mac; }

        /**
         * \brief Getter for the source's mac address.
         *
         * \return Returns the source's mac address as a constant uint8_t pointer.
         */
        address_type src_addr() const { return _eth.src_mac; }

        /**
         * \brief Getter for the interface.
         *
         * \return Returns the interface's index as an uint32_t.
         */
        const NetworkInterface &iface() const { return this->_iface; }

        /**
         * \brief Getter for the length field.
         * \return The length field value.
         */
        uint16_t length() const { return Endian::be_to_host(_eth.length); };

        /* Setters */

        /**
         * \brief Setter for the destination's MAC.
         *
         * \param new_dst_mac uint8_t array of 6 bytes containing the new destination's MAC.
         */
        void dst_addr(const address_type &new_dst_mac);

        /**
         * \brief Setter for the source's MAC.
         *
         * \param new_src_mac uint8_t array of 6 bytes containing the new source's MAC.
         */
        void src_addr(const address_type &new_src_mac);

        /**
         * \brief Setter for the interface.
         *
         * \param new_iface_index uint32_t containing the new interface index.
         */
        void iface(const NetworkInterface &new_iface_index);

        /**
         * \brief Setter for the length field.
         *
         * \param new_length uint16_t with the new value of the length field.
         */
        void length(uint16_t new_length);

        /* Virtual methods */
        /**
         * \brief Returns the IEEE802_3 frame's header length.
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
        PDUType pdu_type() const { return PDU::IEEE802_3; }

        /** \brief Clones this pdu, filling the corresponding header with data
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
        IEEE802_3 *clone_pdu() const {
            return new IEEE802_3(*this);
        }
    private:
        /**
         * Struct that represents the Ethernet II header
         */
        struct ethhdr {
            uint8_t dst_mac[address_type::address_size];
            uint8_t src_mac[address_type::address_size];
            uint16_t length;
        } __attribute__((__packed__));

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);


        ethhdr _eth;
        NetworkInterface _iface;
    };

};


#endif // TINS_IEEE802_3_H
