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

#ifndef __UDP_H
#define __UDP_H


#include "pdu.h"

namespace Tins {

    /** \brief UDP represents the UDP PDU.
     *
     * UDP is the representation of the UDP PDU. Instances of this class
     * must be sent over a level 3 PDU, this will otherwise fail.
     */
    class UDP : public PDU {
    public:
        /** \brief UDP constructor.
         *
         * Creates an instance of UDP. Destination and source port can
         * be provided, otherwise both will be 0.
         * \param dport Destination port.
         * \param sport Source port.
         * */
        UDP(uint16_t sport = 0, uint16_t dport = 0);


         /** \brief Returns the destination port
          */
        inline uint16_t dport() const { return _udp.dport; }

        /** \brief Returns the source port
          */
        inline uint16_t sport() const { return _udp.sport; }

        /** \brief Set the destination port.
         *
         * \param new_dport The new destination port.
         */
        void dport(uint16_t new_dport);

        /** \brief Set the source port.
         *
         * \param new_sport The new source port.
         */
        void sport(uint16_t new_sport);

        /** \brief Set the payload.
         *
         * Payload is NOT copied. Therefore, pointers provided as
         * payloads must be freed manually by the user. This actually
         * creates a RawPDU that holds the payload, and sets it as the
         * inner_pdu. Therefore, if an inner_pdu was set previously,
         * a call to UDP::payload will delete it.
         * \param new_payload New payload.
         * \param new_payload_size New payload's size
         */
        void payload(uint8_t *new_payload, uint32_t new_payload_size);

        /** \brief Returns the header size.
         *
         * This metod overrides PDU::header_size. This size includes the
         * payload and options size. \sa PDU::header_size
         */
        uint32_t header_size() const;

        PDUType pdu_type() const { return PDU::UDP; }

    private:
        struct udphdr {
            uint16_t sport;
            uint16_t dport;
            uint16_t len;
            uint16_t check;
        } __attribute__((packed));

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        udphdr _udp;
    };
};

#endif
