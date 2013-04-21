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


#ifndef TINS_ARP_H
#define TINS_ARP_H

#include "macros.h"
#include "pdu.h"
#include "endianness.h"
#include "hw_address.h"
#include "ip_address.h"

namespace Tins {
    class NetworkInterface;
    class EthernetII;

    /**
     * \brief Class that represents an ARP PDU.
     *
     */
    class ARP : public PDU {
    public:
        /**
         * The type of the hardware address.
         */
        typedef HWAddress<6> hwaddress_type;
        
        /**
         * The type of the IP address.
         */
        typedef IPv4Address ipaddress_type;
    
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
        ARP(ipaddress_type target_ip = ipaddress_type(), 
            ipaddress_type sender_ip = ipaddress_type(), 
            const hwaddress_type &target_hw = hwaddress_type(), 
            const hwaddress_type &sender_hw = hwaddress_type());

        /**
         * \brief Constructs an ARP object from a buffer.
         * 
         * If there is not enough size for an ARP header in the buffer,
         * a malformed_packet exception is thrown. 
         * 
         * If the buffer is bigger than the size of the ARP header, 
         * then the extra data is stored in a RawPDU.
         * 
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        ARP(const uint8_t *buffer, uint32_t total_sz);

        /* Getters */
        /**
         * \brief Getter for the sender's hardware address.
         *
         * \return The sender hardware address.
         */
        hwaddress_type sender_hw_addr() const { return _arp.ar_sha; }

        /**
         * \brief Getter for the sender's IP address.
         *
         * \return The sender IP address.
         */
        ipaddress_type sender_ip_addr() const { return ipaddress_type(_arp.ar_sip); }

        /**
         * \brief Getter for the target's hardware address.
         *
         * \return The target hardware address.
         */
        hwaddress_type target_hw_addr() const { return _arp.ar_tha; }

        /**
         * \brief Getter for the target's IP address.
         *
         * \return The target IP address.
         */
        ipaddress_type target_ip_addr() const { return ipaddress_type(_arp.ar_tip); }

        /**
         * \brief Getter for the hardware address format.
         *
         * \return The hardware address format.
         */
        uint16_t hw_addr_format() const { return Endian::be_to_host(_arp.ar_hrd); }

        /**
         * \brief Getter for the protocol address format.
         *
         * \return The protocol address format.
         */
        uint16_t prot_addr_format() const { return Endian::be_to_host(_arp.ar_pro); }

        /**
         * \brief Getter for the hardware address length.
         *
         * \return The hardware address length.
         */
        uint8_t hw_addr_length() const { return _arp.ar_hln; }

        /**
         * \brief Getter for the protocol address length.
         *
         * \return The protocol address length.
         */
        uint8_t prot_addr_length() const { return _arp.ar_pln; }

        /**
         * \brief Getter for the ARP opcode.
         *
         * \return The ARP opcode.
         */
        uint16_t opcode() const { return Endian::be_to_host(_arp.ar_op); }

        /** \brief Getter for the header size.
         * \return Returns the ARP header size.
         * \sa PDU::header_size
         */
        uint32_t header_size() const;
        /* Setters */

        /**
         * \brief Setter for the sender's hardware address.
         *
         * \param new_snd_hw_addr The new sender hardware address.
         */
        void sender_hw_addr(const hwaddress_type &new_snd_hw_addr);

        /**
         * \brief Setter for the sender's IP address.
         *
         * \param new_snd_ip_addr The new sender IP address.
         */
        void sender_ip_addr(ipaddress_type new_snd_ip_addr);

        /**
         * \brief Setter for the target's hardware address.
         *
         * \param new_tgt_hw_addr The new target hardware address.
         */
        void target_hw_addr(const hwaddress_type &new_tgt_hw_addr);

        /**
         * \brief Setter for the target's IP address.
         *
         * \param new_tgt_ip_addr The new target IP address.
         */
        void target_ip_addr(ipaddress_type new_tgt_ip_addr);

        /**
         * \brief Setter for the hardware address format.
         *
         * \param new_hw_addr_fmt The new hardware address format.
         */
        void hw_addr_format(uint16_t new_hw_addr_fmt);

        /**
         * \brief Setter for the protocol address format.
         *
         * \param new_prot_addr_fmt The new protocol address format.
         */
        void prot_addr_format(uint16_t new_prot_addr_fmt);

        /**
         * \brief Setter for the hardware address length.
         *
         * \param new_hw_addr_len The new hardware address length.
         */
        void hw_addr_length(uint8_t new_hw_addr_len);

        /**
         * \brief Setter for the protocol address length.
         *
         * \param new_prot_addr_len The new protocol address length.
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
         * \brief Creates an ARP Request within an EthernetII PDU.
         *
         * Creates an ARP Request PDU and embeds it within a Layer 2 PDU ready to be
         * sent. 
         *
         * \param target IPv4Address with the target's IP.
         * \param sender IPv4Address with the sender's IP.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address.
         * \return Returns a EthernetII containing the ARP Request.
         */
        static EthernetII make_arp_request(ipaddress_type target, 
          ipaddress_type sender, const hwaddress_type &hw_snd = hwaddress_type());

        /**
         * \brief Creates an ARP Reply within an EthernetII PDU.
         *
         * Creates an ARP Reply PDU and embeds it within a Layer 2 PDU ready to be
         * sent. 
         *
         * \param target IPv4Address with the target's IP.
         * \param sender IPv4Address with the sender's IP.
         * \param hw_tgt uint8_t array of 6 bytes containing the target's hardware address.
         * \param hw_snd uint8_t array of 6 bytes containing the sender's hardware address.
         * \return Returns an EthetnetII containing the ARP Replay.
         */
        static EthernetII make_arp_reply(ipaddress_type target, 
          ipaddress_type sender, const hwaddress_type &hw_tgt = hwaddress_type(), 
          const hwaddress_type &hw_snd = hwaddress_type());

        /** \brief Check wether ptr points to a valid response for this PDU.
         *
         * \sa PDU::matches_response
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        bool matches_response(uint8_t *ptr, uint32_t total_sz);

        /** 
         * \brief Clones this pdu, filling the corresponding header with data
         * extracted from a buffer.
         *
         * \deprecated This method is obsolete.
         * 
         * \param ptr The pointer to the from from which the data will be extracted.
         * \param total_sz The size of the buffer.
         * \return The cloned PDU.
         * \sa PDU::clone_packet
         */
        TINS_DEPRECATED(PDU *clone_packet(const uint8_t *ptr, uint32_t total_sz));
        
        /**
         * \sa PDU::clone
         */
        ARP *clone() const {
            return new ARP(*this);
        }
    private:
        TINS_BEGIN_PACK
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
        } TINS_END_PACK;

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        arphdr _arp;
    };
}
#endif //TINS_ARP_H
