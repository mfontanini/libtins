/*
 * Copyright (c) 2014, Matias Fontanini
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

#ifndef TINS_BOOTP_H
#define TINS_BOOTP_H

#include <stdint.h>
#include <algorithm>
#include <vector>
#include "pdu.h"
#include "macros.h"
#include "endianness.h"
#include "ip_address.h"
#include "hw_address.h"


namespace Tins {

    /**
     * \class BootP
     * \brief Class representing a BootP packet.
     */
    class BootP : public PDU {
    public:
        /**
         * The type of the IP addresses.
         */
        typedef IPv4Address ipaddress_type;

        /**
         * The type of the chaddr field.
         */
        typedef HWAddress<16> chaddr_type;

        /**
         * The type of the vend field.
         */
        typedef std::vector<uint8_t> vend_type;

        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::BOOTP;

        /**
         * \brief Enum which contains the different opcodes BootP messages.
         */
        enum OpCodes {
            BOOTREQUEST = 1,
            BOOTREPLY = 2
        };

        /**
         * \brief Creates an instance of BootP.
         *
         * This sets the size of the vend field to 64, as the BootP RFC
         * states.
         */
        BootP();

        /**
         * \brief Constructs a BootP object from a buffer .
         *
         * If there's not enough size for a BootP header, then a
         * malformed_packet exception is thrown.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         * \param vend_field_size The vend field size to allocate.
         * Subclasses might use 0 to provide their own interpretation of this field.
         */
        BootP(const uint8_t *buffer, uint32_t total_sz, uint32_t vend_field_size = 64);

        /* Getters */

        /**
         * \brief Getter for the opcode field.
         * \return The opcode field for this BootP PDU.
         */
        uint8_t opcode() const { return _bootp.opcode; }

        /**
         * \brief Getter for the htype field.
         * \return The htype field for this BootP PDU.
         */
        uint8_t htype() const { return _bootp.htype; }

        /**
         * \brief Getter for the hlen field.
         * \return The hlen field for this BootP PDU.
         */
        uint8_t hlen() const { return _bootp.hlen; }

        /**
         * \brief Getter for the hops field.
         * \return The hops field for this BootP PDU.
         */
        uint8_t hops() const { return _bootp.hops; }

        /**
         * \brief Getter for the xid field.
         * \return The xid field for this BootP PDU.
         */
        uint32_t xid() const { return Endian::be_to_host(_bootp.xid); }

        /**
         * \brief Getter for the secs field.
         * \return The secs field for this BootP PDU.
         */
        uint16_t secs() const { return Endian::be_to_host(_bootp.secs); }

        /** \brief Getter for the padding field.
         * \return The padding field for this BootP PDU.
         */
        uint16_t padding() const { return Endian::be_to_host(_bootp.padding); }

        /**
         * \brief Getter for the ciaddr field.
         * \return The ciaddr field for this BootP PDU.
         */
        ipaddress_type ciaddr() const { return ipaddress_type(_bootp.ciaddr); }

        /**
         * \brief Getter for the yiaddr field.
         * \return The yiaddr field for this BootP PDU.
         */
        ipaddress_type yiaddr() const { return ipaddress_type(_bootp.yiaddr); }

        /**
         * \brief Getter for the siaddr field.
         * \return The siaddr field for this BootP PDU.
         */
        ipaddress_type siaddr() const { return ipaddress_type(_bootp.siaddr); }

        /**
         * \brief Getter for the giaddr field.
         * \return The giaddr field for this BootP PDU.
         */
        ipaddress_type giaddr() const { return ipaddress_type(_bootp.giaddr); }

        /**
         * \brief Getter for the chaddr field.
         * \return The chddr field for this BootP PDU.
         */
        chaddr_type chaddr() const { return _bootp.chaddr; }

        /**
         * \brief Getter for the sname field.
         * \return The sname field for this BootP PDU.
         */
        const uint8_t *sname() const { return _bootp.sname; }

        /**
         * \brief Getter for the file field.
         * \return The file field for this BootP PDU.
         */
        const uint8_t *file() const { return _bootp.file; }

        /**
         * \brief Getter for the vend field.
         * \return The vend field for this BootP PDU.
         */
        const vend_type &vend() const { return _vend; }

        /**
         * \brief Getter for the header size.
         * \return Returns the BOOTP header size.
         * \sa PDU::header_size
         */
        uint32_t header_size() const;
        /* Setters */

        /**
         * \brief Setter for the opcode field.
         * \param new_opcode The opcode to be set.
         */
        void opcode(uint8_t new_opcode);

        /**
         * \brief Setter for the htype field.
         * \param new_htype The htype to be set.
         */
        void htype(uint8_t new_htype);

        /**
         * \brief Setter for the hlen field.
         * \param new_hlen The hlen to be set.
         */
        void hlen(uint8_t new_hlen);

        /**
         * \brief Setter for the hops field.
         * \param new_hops The hops to be set.
         */
        void hops(uint8_t new_hops);

        /**
         * \brief Setter for the xid field.
         * \param new_xid The xid to be set.
         */
        void xid(uint32_t new_xid);

        /**
         * \brief Setter for the secs field.
         * \param new_secs The secs to be set.
         */
        void secs(uint16_t new_secs);

        /**
         * \brief Setter for the padding field.
         * \param new_padding The padding to be set.
         */
        void padding(uint16_t new_padding);

        /**
         * \brief Setter for the ciaddr field.
         * \param new_ciaddr The ciaddr to be set.
         */
        void ciaddr(ipaddress_type new_ciaddr);

        /**
         * \brief Setter for the yiaddr field.
         * \param new_yiaddr The yiaddr to be set.
         */
        void yiaddr(ipaddress_type new_yiaddr);

        /**
         * \brief Setter for the siaddr field.
         * \param new_siaddr The siaddr to be set.
         */
        void siaddr(ipaddress_type new_siaddr);

        /**
         * \brief Setter for the giaddr field.
         * \param new_giaddr The giaddr to be set.
         */
        void giaddr(ipaddress_type new_giaddr);

        /**
         * \brief Setter for the chaddr field.
         * The new_chaddr pointer must be at least BOOTP::hlen() bytes long.
         * \param new_chaddr The chaddr to be set.
         */
        template<size_t n>
        void chaddr(const HWAddress<n> &new_chaddr) {
            // Copy the new addr
            uint8_t *end = std::copy(
                new_chaddr.begin(),
                new_chaddr.begin() + std::min(n, sizeof(_bootp.chaddr)),
                _bootp.chaddr
            );
            // Fill what's left with zeros
            if(end < _bootp.chaddr + chaddr_type::address_size)
                std::fill(end, _bootp.chaddr + chaddr_type::address_size, 0);
        }

        /**
         * \brief Setter for the sname field.
         * \param new_sname The sname to be set.
         */
        void sname(const uint8_t *new_sname);

        /**
         * \brief Setter for the file field.
         * \param new_file The file to be set.
         */
        void file(const uint8_t *new_file);

        /**
         * \brief Setter for the vend field.
         * \param new_vend The vend to be set.
         */
        void vend(const vend_type &new_vend);

        /**
         * \brief Check whether ptr points to a valid response for this PDU.
         *
         * This returns true if the xid field is equal.
         *
         * \sa PDU::matches_response
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        bool matches_response(const uint8_t *ptr, uint32_t total_sz) const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \sa PDU::clone
         */
        BootP *clone() const {
            return new BootP(*this);
        }
    protected:
        /**
         * \brief Getter for the vend field.
         *
         * This getter can be used by subclasses to avoid copying the
         * vend field around.
         *
         * \return The vend field for this BootP PDU.
         */
        vend_type &vend() { return _vend; }

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
    private:
        /**
         * Struct that represents the Bootp datagram.
         */
        TINS_BEGIN_PACK
        struct bootphdr {
            uint8_t opcode;
            uint8_t htype;
            uint8_t hlen;
            uint8_t hops;
            uint32_t xid;
            uint16_t secs;
            uint16_t padding;
            uint32_t ciaddr;
            uint32_t yiaddr;
            uint32_t siaddr;
            uint32_t giaddr;
            uint8_t chaddr[16];
            uint8_t sname[64];
            uint8_t file[128];
        } TINS_END_PACK;

        bootphdr _bootp;
        vend_type _vend;
    };
}

#endif // TINS_BOOTP_H
