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

#ifndef TINS_UDP_H
#define TINS_UDP_H


#include "pdu.h"
#include "endianness.h"

namespace Tins {

    /** \brief Class that represents an UDP PDU.
     *
     * UDP is the representation of the UDP PDU. Instances of this class
     * must be sent over a level 3 PDU, this will otherwise fail.
     */
    class UDP : public PDU {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::UDP;
    
        /** 
         * \brief UDP constructor.
         *
         * Creates an instance of UDP. Destination and source port can
         * be provided, otherwise both will be 0.
         * \param dport Destination port.
         * \param sport Source port.
         * \param child The child PDU(optional).
         * */
        UDP(uint16_t dport = 0, uint16_t sport = 0, PDU *child = 0);

        /**
         * \brief Constructor which creates an UDP object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        UDP(const uint8_t *buffer, uint32_t total_sz);
        
        /** 
         * \brief Getter for the destination port.
         * \return The datagram's destination port.
         */
        uint16_t dport() const { return Endian::be_to_host(_udp.dport); }

        /** 
         * \brief Getter for the source port.
         * \return The datagram's source port.
         */
        uint16_t sport() const { return Endian::be_to_host(_udp.sport); }
        
        /**
         * \brief Getter for the length of the datagram.
         * \return The length of the datagram.
         */
        uint16_t length() const { return Endian::be_to_host(_udp.len); }

        /** 
         * \brief Set the destination port.
         * \param new_dport The new destination port.
         */
        void dport(uint16_t new_dport);

        /** \brief Set the source port.
         *
         * \param new_sport The new source port.
         */
        void sport(uint16_t new_sport);
        
        /** \brief Getter for the length field.
         * \param new_len The new length field.
         * \return The length field.
         */
        void length(uint16_t new_len);

        /** \brief Returns the header size.
         *
         * This metod overrides PDU::header_size. This size includes the
         * payload and options size. \sa PDU::header_size
         */
        uint32_t header_size() const;
        
        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::UDP; }
        
        /**
         * \sa PDU::clone_pdu
         */
        PDU *clone_pdu() const {
            return new UDP(*this);
        }
    private:
        struct udphdr {
            uint16_t sport;
            uint16_t dport;
            uint16_t len;
            uint16_t check;
        } __attribute__((packed));

        void copy_fields(const UDP *other);
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        udphdr _udp;
    };
};

#endif // TINS_UDP_H
