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

    /** \brief Base class for protocol data units.
     *
     * Every PDU implementation must inherit this one. PDUs can be serialized,
     * therefore allowing a PacketSender to send them through the corresponding
     * sockets. PDUs are created upwards: upper layers will be children of the
     * lower ones. Each PDU must provide its flag identifier. This will be most
     * likely added to its parent's data, hence it should be a valid identifier.
     * For example, IP should provide IPPROTO_IP.
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
            RADIOTAP,
            DOT11,
            DOT11_ACK,
            DOT11_ASSOC_REQ,
            DOT11_ASSOC_RESP,
            DOT11_AUTH,
            DOT11_BEACON,
            DOT11_BLOCK_ACK,
            DOT11_BLOCK_ACK_REQ,
            DOT11_CF_END,
            DOT11_DATA,
            DOT11_CONTROL,
            DOT11_DEAUTH,
            DOT11_DIASSOC,
            DOT11_END_CF_ACK,
            DOT11_MANAGEMENT,
            DOT11_PROBE_REQ,
            DOT11_PROBE_RESP,
            DOT11_PS_POLL,
            DOT11_REASSOC_REQ,
            DOT11_REASSOC_RESP,
            DOT11_RTS,
            DOT11_QOS_DATA,
            SNAP,
            IP,
            ARP,
            TCP,
            UDP,
            ICMP,
            BOOTP,
            DHCP,
            EAPOL,
            RC4EAPOL,
            RSNEAPOL
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

        /**
         * \brief Getter for this PDU's type flag identifier.
         * \return The type flag identifier.
         */
        inline uint32_t flag() const { return _flag; }

        /**
         * \brief Getter for the inner PDU.
         * \return The current inner PDU. Might be 0.
         */
        inline PDU *inner_pdu() const { return _inner_pdu; }

        /** \brief Sets the flag identifier.
         */
        void flag(uint32_t new_flag);

        /**
         * \brief Sets the child PDU.
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

        /**
         * \brief Find and returns the first PDU that matches the given flag.
         *
         * This method searches for the first PDU which has the same type flag as
         * the given one. If the first PDU matches that flag, it is returned.
         * If no PDU matches, 0 is returned.
         * \param flag The flag which being searched.
         */
        template<class T> T *find_inner_pdu(PDUType type) {
            PDU *pdu = this;
            while(pdu) {
                if(pdu->pdu_type() == type)
                    return static_cast<T*>(pdu);
                pdu = pdu->inner_pdu();
            }
            return 0;
        }

        /**
         * \brief Clones this packet.
         *
         * This method clones this PDU and clones every inner PDU,
         * therefore obtaining a clone of the whole inner PDU chain.
         * The pointer returned must be deleted by the user.
         * \return A pointer to a clone of this packet.
         */
        PDU *clone_packet() const;

        /**
         * \brief Clones this PDU.
         *
         * This method does not clone the inner PDUs. \sa PDU::clone_packet
         * \return A pointer to a copy of this PDU.
         */
        virtual PDU *clone_pdu() const {
            /* Should be pure virtual. It's this way to avoid compiling issues.
             * Once every pdu has implemented it, make it pure virtual. */
            return 0;
        }

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
         * \brief Check wether this PDU matches the specified flag.
         *
         * This method should be reimplemented in PDU classes which have
         * subclasses, and try to match the given PDU to each of its parent
         * classes' flag.
         * \param flag The flag to match.
         */
        virtual bool matches_flag(PDUType flag) {
           return flag == pdu_type();
        }

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
        /**
         * \brief Copy constructor.
         */
        PDU(const PDU &other);

        /**
         * \brief Copy assignment operator.
         */
        PDU &operator=(const PDU &other);

        /**
         * \brief Copy other PDU's inner PDU(if any).
         * \param pdu The PDU from which to copy the inner PDU.
         */
        void copy_inner_pdu(const PDU &pdu);


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
    private:
        uint32_t _flag;
        PDU *_inner_pdu;
    };
};

#endif
