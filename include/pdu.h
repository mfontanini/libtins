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

#ifndef __PDU_H
#define __PDU_H


#include <stdint.h>
#include "packetsender.h"

/** \brief The Tins namespace.
 */
namespace Tins {

    class PacketSender;

    /** \brief PDU is the base class for protocol data units.
     *
     * Every PDU implementation must inherit this one. PDUs can be serialized,
     * therefore allowing a PacketSender to send them through sockets. PDUs
     * are created upwards: upper layers will be children of the lower ones.
     * Each PDU must provide its flag identifier. This will be most likely added
     * to its parent's data, hence it should be a valid identifier. For example,
     * IP should provide IPPROTO_IP.
     */
    class PDU {
    public:

        /**
         * \brief Enum which identifies each type of PDU.
         *
         * This enum is used to identify the PDU type.
         */
        enum PDUType {
            RAW,
            ETHERNET_II,
            IEEE802_11,
            SNAP,
            RADIOTAP,
            IP,
            ARP,
            TCP,
            UDP,
            ICMP,
            DHCP
        };

        /** \brief PDU constructor
         *
         * Must be called by subclasses in their constructors.
         * \param flag The flag identifier for the subclass' PDU.
         * \param next_pdu The child PDU. Can be obviated.
         */
        PDU(uint32_t flag, PDU *next_pdu = 0);

        /** \brief PDU destructor.
         *
         * Deletes the inner pdu, as a consequence every child pdu is
         * deleted.
         */
        virtual ~PDU();

        /** \brief The header's size
         */
        virtual uint32_t header_size() const = 0;

        /** \brief Trailer's size.
         *
         * Some protocols require a trailer(like Ethernet). This defaults to 0.
         */
        virtual uint32_t trailer_size() const { return 0; }

        /** \brief The whole chain of PDU's size, including this one.
         *
         * Returns the sum of this and all children PDUs' size.
         */
        uint32_t size() const;

        /** \brief This PDU's type flag identifier.
         *
         */
        inline uint32_t flag() const { return _flag; }

        /** \brief The child PDU.
         */
        inline PDU *inner_pdu() const { return _inner_pdu; }

        /** \brief Sets the flag identifier.
         */
        void flag(uint32_t new_flag);

        /** \brief Sets the child PDU.
         *
         * \param next_pdu The new child PDU.
         * When setting a new inner_pdu, the instance takesownership of
         * the object, therefore deleting it when it's no longer required.
         */
        void inner_pdu(PDU *next_pdu);


        /** \brief Serializes the whole chain of PDU's, including this one.
         *
         * \param sz The size of the buffer must be returned through this parameter.
         * The buffer returned must be deleted by the user using
         * operator delete[].
         */
        uint8_t *serialize(uint32_t &sz);

        /** \brief Send the stack of PDUs through a PacketSender.
         *
         * This method will be called only for the PDU on the bottom of the stack,
         * therefore it should only implement this method if it can be sent.
         * PacketSender implements specific methods to send packets which start
         * on every valid TCP/IP stack layer; this should only be a proxy for
         * those methods.
         * \param sender The PacketSender which will send the packet.
         */
        virtual bool send(PacketSender *sender) { return false; }

        /** \brief Receives a matching response for this packet.
         *
         * This method should act as a proxy for PacketSender::recv_lX methods.
         * \param sender The packet sender which will receive the packet.
         */
        virtual PDU *recv_response(PacketSender *sender) { return false; }

        /** \brief Check wether ptr points to a valid response for this PDU.
         *
         * This method must check wether the buffer pointed by ptr is a valid
         * response for this PDU. If it is valid, then it might want to propagate
         * the call to the next PDU. Note that in some cases, such as ICMP
         * Host Unreachable, there is no need to ask the next layer for matching.
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        virtual bool matches_response(uint8_t *ptr, uint32_t total_sz) { return false; }

        /**
         * \brief Getter for the PDU's type.
         *
         * \return Returns the PDUType corresponding to the PDU.
         */
        virtual PDUType pdu_type() const = 0;

        /** \brief Clones this pdu, filling the corresponding header with data
         * extracted from a buffer.
         *
         * \param ptr The pointer to the from from which the data will be extracted.
         * \param total_sz The size of the buffer.
         * \return The cloned PDU.
         */
        virtual PDU *clone_packet(const uint8_t *ptr, uint32_t total_sz) { return 0; }
    protected:
        /** \brief Serializes this PDU and propagates this action to child PDUs.
         *
         * \param buffer The buffer in which to store this PDU's serialization.
         * \param total_sz The total size of the buffer.
         * \param parent The parent PDU. Will be 0 if there's the parent does not exist.
         */
        void serialize(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        /** \brief Clones the inner pdu(if any).
         *
         * This method clones the inner pdu using data from a buffer.
         * \param ptr The pointer from which the child PDU must be cloned.
         * \param total_sz The total size of the buffer.
         * \return Returns the cloned PDU. Will be 0 if cloning failed.
         */
        PDU *clone_inner_pdu(const uint8_t *ptr, uint32_t total_sz);

        /** \brief Serializes this TCP PDU.
         *
         * Each PDU must override this method and implement it's own
         * serialization.
         * \param buffer The buffer in which the PDU will be serialized.
         * \param total_sz The size available in the buffer.
         * \param parent The PDU that's one level below this one on the stack. Might be 0.
         */
        virtual void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) = 0;

        /** \brief Does the 16 bits sum of all 2 bytes elements between start and end.
         *
         * This is the checksum used by IP, UDP and TCP. If there's and odd number of
         * bytes, the last one is padded and added to the checksum. The checksum is performed
         * using network endiannes.
         * \param start The pointer to the start of the buffer.
         * \param end The pointer to the end of the buffer(excluding the last element).
         * \return Returns the checksum between start and end(non inclusive).
         */
        static uint32_t do_checksum(uint8_t *start, uint8_t *end);

        /** \brief Performs the pseudo header checksum used in TCP and UDP PDUs.
         *
         * \param source_ip The source ip address.
         * \param dest_ip The destination ip address.
         * \param len The length to be included in the pseudo header.
         * \param flag The flag to use in the protocol field of the pseudo header.
         * \return The pseudo header checksum.
         */
        static uint32_t pseudoheader_checksum(uint32_t source_ip, uint32_t dest_ip, uint32_t len, uint32_t flag);
    private:
        uint32_t _flag;
        PDU *_inner_pdu;
    };
};

#endif
