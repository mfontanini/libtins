/*
 * Copyright (c) 2012, Nasel
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef TINS_UDP_H
#define TINS_UDP_H

#include "macros.h"
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
         * \sa PDU::clone
         */
        PDU *clone() const {
            return new UDP(*this);
        }
    private:
        TINS_BEGIN_PACK
        struct udphdr {
            uint16_t sport;
            uint16_t dport;
            uint16_t len;
            uint16_t check;
        } TINS_END_PACK;

        void copy_fields(const UDP *other);
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        udphdr _udp;
    };
};

#endif // TINS_UDP_H
