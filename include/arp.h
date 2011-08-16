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


#ifndef __ARP_H
#define __ARP_H


#include <string>
#include "pdu.h"

namespace Tins {

    /**
     * \brief Class that represents an ARP PDU.
     *
     */
    class ARP : public PDU {
    public:
        /**
         * \brief Enum which indicates the type of ARP packet.
         */
        enum Flags {
            REQUEST = 0x0100,
            REPLY   = 0x0200
        };

        /**
         * \brief Default constructor for ARP PDU objects.
         */
        ARP();

        /* Getters */
        /**
         * \brief Getter for the sender's hardware address.
         *
         * \return Returns the sender's hardware address in an uint8_t*.
         */
        inline const uint8_t* sender_hw_addr() { return this->_arp.ar_sha; }

        /**
         * \brief Getter for the sender's IP address.
         *
         * \return Returns the sender's IP address in an uint32_t.
         */
        inline const uint32_t sender_ip_addr() { return this->_arp.ar_sip; }

        /**
         * \brief Getter for the target's hardware address.
         *
         * \return Returns the target's hardware address in an uint8_t*.
         */
        inline const uint8_t* target_hw_addr() { return this->_arp.ar_tha; }

        /**
         * \brief Getter for the target's IP address.
         *
         * \return Returns the target's IP address in an uint32_t.
         */
        inline const uint32_t target_ip_addr() { return this->_arp.ar_tip; }

        /**
         * \brief Getter for the hardware address format.
         *
         * \return Returns the hardware address' format in an uint16_t.
         */
        inline uint16_t hw_addr_format() { return this->_arp.ar_hrd; }

        /**
         * \brief Getter for the protocol address format.
         *
         * \return Returns the protocol address' format in an uint16_t.
         */
        inline uint16_t prot_addr_format() { return this->_arp.ar_pro; }

        /**
         * \brief Getter for the hardware address length.
         *
         * \return Returns the hardware address' length in an uint8_t.
         */
        inline uint8_t hw_addr_length() { return this->_arp.ar_hln; }

        /**
         * \brief Getter for the protocol address length.
         *
         * \return Returns the protocol address' length in an uint8_t.
         */
        inline uint8_t prot_addr_length() { return this->_arp.ar_pln; }

        /**
         * \brief Getter for the ARP opcode.
         *
         * \return Returns the ARP opcode in an uint16_t.
         */
        inline uint16_t opcode() { return this->_arp.ar_op; }

        /* Setters */

        /**
         * \brief Setter for the sender's hardware address.
         *
         * \param new_snd_hw_addr uint8_t array containing the new sender's hardware address.
         */
        void sender_hw_addr(uint8_t* new_snd_hw_addr);

        /**
         * \brief Setter for the sender's IP address.
         *
         * \param new_snd_ip_addr uint32_t containing the new sender's IP address.
         */
        void sender_ip_addr(uint32_t new_snd_ip_addr);

        /**
         * \brief Setter for the target's hardware address.
         *
         * \param new_tgt_hw_addr uint8_t array containing the new target's hardware address.
         */
        void target_hw_addr(uint8_t* new_tgt_hw_addr);

        /**
         * \brief Setter for the target's IP address.
         *
         * \param new_tgt_ip_addr uint32_t containing the new target's IP address.
         */
        void target_ip_addr(uint32_t new_tgt_ip_addr);

        /**
         * \brief Setter for the hardware address format.
         *
         * \param new_hw_addr_fmt uint16_t with the new hardware address' format.
         */
        void hw_addr_format(uint16_t new_hw_addr_fmt);

        /**
         * \brief Setter for the protocol address format.
         *
         * \param new_prot_addr_fmt uint16_t with the new protocol address' format.
         */
        void prot_addr_format(uint16_t new_prot_addr_fmt);

        /**
         * \brief Setter for the hardware address length.
         *
         * \param new_hw_addr_len uint8_t with the new hardware address' length.
         */
        void hw_addr_length(uint8_t new_hw_addr_len);

        /**
         * \brief Setter for the protocol address length.
         *
         * \param new_prot_addr_len uint8_t with the new protocol address' length.
         */
        void prot_addr_length(uint8_t new_prot_addr_len);

        /**
         * \brief Setter for the ARP opcode.
         *
         * \param new_opcode Flag enum value of the ARP opcode to set.
         */
        void opcode(Flags new_opcode);

        /** \brief Check wether ptr points to a valid response for this PDU.
         *
         * \sa PDU::matches_response
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        bool matches_response(uint8_t *ptr, uint32_t total_sz);

        uint32_t header_size() const;

        /** \brief Clones this pdu, filling the corresponding header with data
         * extracted from a buffer.
         *
         * \param ptr The pointer to the from from which the data will be extracted.
         * \param total_sz The size of the buffer.
         * \return The cloned PDU.
         * \sa PDU::clone_packet
         */
        PDU *clone_packet(uint8_t *ptr, uint32_t total_sz);

        PDUType pdu_type() const { return PDU::ARP; }

        /**
         * \brief Creates an ARP Request within a Layer 2 PDU using strings for target and sender.
         *
         * Creates an ARP Request PDU and embeds it within a Layer 2 PDU ready to be
         * sent. The target and sender's protocol address are given using strings.
         *
         * \param iface string with the interface from where to send the ARP.
         * \param target string with the target's IP or hostname.
         * \param sender string with the sender's IP or hostname.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address.
         * \return Returns a PDU* to the new Layer 2 PDU containing the ARP Request.
         */
        static PDU* make_arp_request(const std::string& iface, const std::string &target, const std::string &sender, const uint8_t* hw_snd = 0);

        /**
         * \brief Creates an ARP Request within a Layer 2 PDU using uint32_t for target and sender.
         *
         * Creates an ARP Request PDU and embeds it within a Layer 2 PDU ready to be
         * sent. The target and sender's protocol address are given using uint32_t.
         *
         * \param iface string with the interface from where to send the ARP.
         * \param target uint32_t with the target's IP.
         * \param sender uint32_t with the sender's IP.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address.
         * \return Returns a PDU* to the new Layer 2 PDU containing the ARP Request.
         */
        static PDU* make_arp_request(const std::string& iface, uint32_t target, uint32_t sender, const uint8_t* hw_snd = 0);

        /**
         * \brief Creates an ARP Reply within a Layer 2 PDU using strings for target and sender.
         *
         * Creates an ARP Reply PDU and embeds it within a Layer 2 PDU ready to be
         * sent. The target and sender's protocol address are given using strings.
         *
         * \param iface string with the interface from where to send the ARP.
         * \param target string with the target's IP or hostname.
         * \param sender string with the sender's IP or hostname.
         * \param hw_tgt uint8_t array of 6 bytes containing the target's hardware address.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address.
         * \return Returns a PDU* to the new Layer 2 PDU containing the ARP Replay.
         */
        static PDU* make_arp_reply(const std::string& iface, const std::string &target, const std::string &sender, const uint8_t* hw_tgt, const uint8_t* hw_snd);

        /**
         * \brief Creates an ARP Reply within a Layer 2 PDU using uint32_t for target and sender.
         *
         * Creates an ARP Reply PDU and embeds it within a Layer 2 PDU ready to be
         * sent. The target and sender's protocol address are given using uint32_t.
         *
         * \param iface string with the interface from where to send the ARP.
         * \param target uint32_t with the target's IP.
         * \param sender uint32_t with the sender's IP.
         * \param hw_tgt uint8_t array of 6 bytes containing the target's hardware address.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address.
         * \return Returns a PDU* to the new Layer 2 PDU containing the ARP Replay.
         */
        static PDU* make_arp_reply(const std::string& iface, uint32_t target, uint32_t sender, const uint8_t* hw_tgt, const uint8_t* hw_snd);

        /**
         * \brief Converts the current ARP PDU to an ARP Request.
         *
         * Calling this method sets the values of the target ARP PDU to become
         * an ARP Request PDU.
         *
         * \param ip_tgt string with the target's IP or hostname.
         * \param ip_snd string with the sender's IP or hostname.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address(optional).
         */
        void set_arp_request(const std::string& ip_tgt, const std::string& ip_snd, const uint8_t* hw_snd = 0);

        /**
         * \brief Converts the current ARP PDU to an ARP Reply.
         *
         * Calling this method sets the values of the target ARP PDU to become
         * an ARP Reply PDU.
         *
         * \param ip_tgt string with the target's IP or hostname.
         * \param ip_snd string with the sender's IP or hostname.
         * \param hw_tgt uint8_t array of 6 bytes containing the target's hardware address.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address.
         */
         void set_arp_reply(const std::string& ip_tgt, const std::string& ip_snd, const uint8_t* hw_tgt, const uint8_t* hw_snd);

    private:
        struct arphdr {
            uint16_t ar_hrd;	/* format of hardware address	*/
            uint16_t ar_pro;	/* format of protocol address	*/
            uint8_t	ar_hln;		/* length of hardware address	*/
            uint8_t	ar_pln;		/* length of protocol address	*/
            uint16_t ar_op;		/* ARP opcode (command)		*/

            uint8_t ar_sha[6];	/* sender hardware address	*/
            uint32_t ar_sip;	/* sender IP address		*/
            uint8_t ar_tha[6];	/* target hardware address	*/
            uint32_t ar_tip;	/* target IP address		*/
        } __attribute__((__packed__));

        /** \brief Creates an instance of ARP using an arphdr pointer.
         *
         * \param arp_ptr The pointer to the arphdr.
         */
        ARP(arphdr *arp_ptr);

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        arphdr _arp;
    };
};
#endif
