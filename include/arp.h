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


#ifndef TINS_ARP_H
#define TINS_ARP_H


#include <string>
#include "pdu.h"
#include "ipaddress.h"
#include "utils.h"
#include "hwaddress.h"
#include "network_interface.h"

namespace Tins {

    /**
     * \brief Class that represents an ARP PDU.
     *
     */
    class ARP : public PDU {
    public:
        typedef HWAddress<6> hwaddress_type;
    
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::ARP;
    
        /**
         * \brief Enum which indicates the type of ARP packet.
         */
        enum Flags {
            REQUEST = 0x0001,
            REPLY   = 0x0002
        };

        /**
         * \brief Default constructor for ARP PDU objects.
         *
         * ARP requests and replies can be constructed easily using
         * ARP::make_arp_request/reply static functions.
         */
        ARP(IPv4Address target_ip = IPv4Address(), 
            IPv4Address sender_ip = IPv4Address(), 
            const hwaddress_type &target_hw = hwaddress_type(), 
            const hwaddress_type &sender_hw = hwaddress_type());

        /**
         * \brief Constructor which creates an ARP object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        ARP(const uint8_t *buffer, uint32_t total_sz);

        /* Getters */
        /**
         * \brief Getter for the sender's hardware address.
         *
         * \return Returns the sender's hardware address in an uint8_t*.
         */
        hwaddress_type sender_hw_addr() const { return _arp.ar_sha; }

        /**
         * \brief Getter for the sender's IP address.
         *
         * \return Returns the sender's IP address in an uint32_t.
         */
        IPv4Address sender_ip_addr() const { return Utils::net_to_host_l(_arp.ar_sip); }

        /**
         * \brief Getter for the target's hardware address.
         *
         * \return Returns the target's hardware address in an uint8_t*.
         */
        hwaddress_type target_hw_addr() const { return _arp.ar_tha; }

        /**
         * \brief Getter for the target's IP address.
         *
         * \return Returns the target's IP address in an uint32_t.
         */
        IPv4Address target_ip_addr() const { return Utils::net_to_host_l(_arp.ar_tip); }

        /**
         * \brief Getter for the hardware address format.
         *
         * \return Returns the hardware address' format in an uint16_t.
         */
        uint16_t hw_addr_format() const { return Utils::net_to_host_s(_arp.ar_hrd); }

        /**
         * \brief Getter for the protocol address format.
         *
         * \return Returns the protocol address' format in an uint16_t.
         */
        uint16_t prot_addr_format() const { return Utils::net_to_host_s(_arp.ar_pro); }

        /**
         * \brief Getter for the hardware address length.
         *
         * \return Returns the hardware address' length in an uint8_t.
         */
        uint8_t hw_addr_length() const { return _arp.ar_hln; }

        /**
         * \brief Getter for the protocol address length.
         *
         * \return Returns the protocol address' length in an uint8_t.
         */
        uint8_t prot_addr_length() const { return _arp.ar_pln; }

        /**
         * \brief Getter for the ARP opcode.
         *
         * \return Returns the ARP opcode in an uint16_t.
         */
        uint16_t opcode() const { return Utils::net_to_host_s(_arp.ar_op); }

        /** \brief Getter for the header size.
         * \return Returns the ARP header size.
         * \sa PDU::header_size
         */
        uint32_t header_size() const;
        /* Setters */

        /**
         * \brief Setter for the sender's hardware address.
         *
         * \param new_snd_hw_addr uint8_t array containing the new sender's hardware address.
         */
        void sender_hw_addr(const hwaddress_type &new_snd_hw_addr);

        /**
         * \brief Setter for the sender's IP address.
         *
         * \param new_snd_ip_addr IPv4Address containing the new sender's IP address.
         */
        void sender_ip_addr(IPv4Address new_snd_ip_addr);

        /**
         * \brief Setter for the target's hardware address.
         *
         * \param new_tgt_hw_addr uint8_t array containing the new target's hardware address.
         */
        void target_hw_addr(const hwaddress_type &new_tgt_hw_addr);

        /**
         * \brief Setter for the target's IP address.
         *
         * \param new_tgt_ip_addr IPv4Address containing the new target's IP address.
         */
        void target_ip_addr(IPv4Address new_tgt_ip_addr);

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

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::ARP; }

        /**
         * \brief Creates an ARP Request within a Layer 2 PDU using uint32_t for target and sender.
         *
         * Creates an ARP Request PDU and embeds it within a Layer 2 PDU ready to be
         * sent. The target and sender's protocol address are given using uint32_t.
         *
         * \param iface string with the interface from where to send the ARP.
         * \param target IPv4Address with the target's IP.
         * \param sender IPv4Address with the sender's IP.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address.
         * \return Returns a PDU* to the new Layer 2 PDU containing the ARP Request.
         */
        static PDU* make_arp_request(const NetworkInterface& iface, IPv4Address target, 
          IPv4Address sender, const hwaddress_type &hw_snd = hwaddress_type());

        /**
         * \brief Creates an ARP Reply within a Layer 2 PDU using uint32_t for target and sender.
         *
         * Creates an ARP Reply PDU and embeds it within a Layer 2 PDU ready to be
         * sent. The target and sender's protocol address are given using uint32_t.
         *
         * \param iface string with the interface from where to send the ARP.
         * \param target IPv4Address with the target's IP.
         * \param sender IPv4Address with the sender's IP.
         * \param hw_tgt uint8_t array of 6 bytes containing the target's hardware address.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address.
         * \return Returns a PDU* to the new Layer 2 PDU containing the ARP Replay.
         */
        static PDU* make_arp_reply(const NetworkInterface& iface, IPv4Address target, 
          IPv4Address sender, const hwaddress_type &hw_tgt = hwaddress_type(), 
          const hwaddress_type &hw_snd = hwaddress_type());

        /** \brief Check wether ptr points to a valid response for this PDU.
         *
         * \sa PDU::matches_response
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        bool matches_response(uint8_t *ptr, uint32_t total_sz);

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
        PDU *clone_pdu() const {
            return do_clone_pdu<ARP>();
        }
    private:
        struct arphdr {
            uint16_t ar_hrd;	/* format of hardware address	*/
            uint16_t ar_pro;	/* format of protocol address	*/
            uint8_t	ar_hln;		/* length of hardware address	*/
            uint8_t	ar_pln;		/* length of protocol address	*/
            uint16_t ar_op;		/* ARP opcode (command)		*/

            /* sender hardware address	*/
            uint8_t ar_sha[hwaddress_type::address_size];	
            /* sender IP address		*/
            uint32_t ar_sip;	
            /* target hardware address	*/
            uint8_t ar_tha[hwaddress_type::address_size];	
            /* target IP address		*/
            uint32_t ar_tip;
        } __attribute__((__packed__));

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        arphdr _arp;
    };
};
#endif //TINS_ARP_H
