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

#ifndef __IEEE802_11_h
#define __IEEE802_11_h

#include <stdint.h>
#include <stdexcept>

#include "pdu.h"
#include "utils.h"

namespace Tins {

    /**
     * \brief Class representing an 802.11 frame.
     */
    class IEEE802_11 : public PDU {

    public:

        /**
         * \brief Constructor for creating a 802.11 PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        IEEE802_11(const std::string& iface, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        IEEE802_11(uint32_t iface_index, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        IEEE802_11(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the protocol version.
         *
         * \return The protocol version in an uint8_t.
         */
        inline uint8_t protocol() const { return this->_header.control.protocol; }

        /**
         * \brief Getter for the 802.11 frame's type.
         *
         * \return The type of the 802.11 frame in an uint8_t.
         */
        inline uint8_t type() const { return this->_header.control.type; }

        /**
         * \brief Getter for the 802.11 frame's subtype.
         *
         * \return The subtype of the 802.11 frame in an uint8_t.
         */
        inline uint8_t subtype() const { return this->_header.control.subtype; }

        /**
         * \brief Getter for the 802.11 frame's "To DS" bit.
         *
         * \return Boolean indicating if the "To DS" bit is set.
         */
        inline bool to_ds() const { return this->_header.control.to_ds; }

        /**
         * \brief Getter for the 802.11 frame's "From DS" bit.
         *
         * \return Boolean indicating if the "From DS" bit is set.
         */
        inline bool from_ds() const { return this->_header.control.from_ds; }

        /**
         * \brief Getter for the 802.11 frame's "More Frag" bit.
         *
         * \return Boolean indicating if the "More Frag" bit is set.
         */
        inline bool more_frag() const { return this->_header.control.more_frag; }

        /**
         * \brief Getter for the 802.11 frame's "Retry" bit.
         *
         * \return Boolean indicating if the "Retry" bit is set.
         */
        inline bool retry() const { return this->_header.control.retry; }

        /**
         * \brief Getter for the 802.11 frame's "Power Management" bit.
         *
         * \return Boolean indicating if the "Power Management" bit is set.
         */
        inline bool power_mgmt() const { return this->_header.control.power_mgmt; }

        /**
         * \brief Getter for the 802.11 frame's "WEP" bit.
         *
         * \return Boolean indicating if the "WEP" bit is set.
         */
        inline bool wep() const { return this->_header.control.wep; }

        /**
         * \brief Getter for the 802.11 frame's "Order" bit.
         *
         * \return Boolean indicating if the "Order" bit is set.
         */
        inline bool order() const { return this->_header.control.order; }

        /**
         * \brief Getter for the duration/id field.
         *
         * \return The value of the duration/id field in an uint16_t.
         */
        inline uint16_t duration_id() const { return Utils::net_to_host_s(this->_header.duration_id); }

        /**
         * \brief Getter for the destination's address.
         *
         * \return The destination's address as a constant uint8_t pointer.
         */
        inline const uint8_t* dst_addr() const { return this->_header.dst_addr; }

        /**
         * \brief Getter for the source's address.
         *
         * \return The source's address as a constant uint8_t pointer.
         */
        inline const uint8_t* src_addr() const { return this->_header.src_addr; }

        /**
         * \brief Getter for the filtering's address.
         *
         * \return The filtering's address as a constant uint8_t pointer.
         */
        inline const uint8_t* filter_addr() const { return this->_header.filter_addr; }

        /**
         * \brief Getter for the fragment number.
         *
         * \return The fragment number as an uint8_t.
         */
        inline uint8_t frag_num() const { return this->_header.seq_control.frag_number; }

        /**
         * \brief Getter for the sequence number.
         *
         * \return The sequence number as an uint16_t.
         */
        inline uint16_t seq_num() const { return Utils::net_to_host_s(this->_header.seq_control.seq_number); }

        /**
         * \brief Getter for the optional address.
         *
         * \return The optional address as a constant uint8_t pointer.
         */
        inline const uint8_t* opt_addr() const { return this->_header.opt_addr; }

        /**
         * \brief Getter for the interface.
         *
         * \return The interface's index as an uint32_t.
         */
        inline uint32_t iface() const { return this->_iface_index; }

        /**
         * \brief Setter for the protocol version.
         *
         * \param new_proto uint8_t with the new protocol version.
         */
        void protocol(uint8_t new_proto);

        /**
         * \brief Setter for the 802.11 frame's type.
         *
         * \param new_type uint8_t with the new type of the 802.11 frame.
         */
        void type(uint8_t new_type);

        /**
         * \brief Setter for the 802.11 frame's subtype.
         *
         * \param new_subtype uint8_t with the new subtype of the 802.11 frame.
         */
        void subtype(uint8_t new_subtype);

        /**
         * \brief Setter for the 802.11 frame's "To DS" bit.
         *
         * \param new_value bool indicating the new value of the flag.
         */
        void to_ds(bool new_value);

        /**
         * \brief Setter for the 802.11 frame's "From DS" bit.
         *
         * \param new_value bool indicating the new value of the flag.
         */
        void from_ds(bool new_value);

        /**
         * \brief Setter for the 802.11 frame's "More Frag" bit.
         *
         * \param new_value bool indicating the new value of the flag.
         */
        void more_frag(bool new_value);

        /**
         * \brief Setter for the 802.11 frame's "Retry" bit.
         *
         * \param new_value bool indicating the new value of the flag.
         */
        void retry(bool new_value);

        /**
         * \brief Setter for the 802.11 frame's "Power Management" bit.
         *
         * \param new_value bool indicating the new value of the flag.
         */
        void power_mgmt(bool new_value);

        /**
         * \brief Setter for the 802.11 frame's "WEP" bit.
         *
         * \param new_value bool indicating the new value of the flag.
         */
        void wep(bool new_value);

        /**
         * \brief Setter for the 802.11 frame's "Order" bit.
         *
         * \param new_value bool indicating the new value of the flag.
         */
        void order(bool new_value);

        /**
         * \brief Setter for the duration/id field.
         *
         * \param new_duration_id uint16_t with the new value of the duration/id field.
         */
        void duration_id(uint16_t new_duration_id);

        /**
         * \brief Setter for the destination's address.
         *
         * \param new_dst_addr const uint8_t array of 6 bytes containing the new destination's address.
         */
        void dst_addr(const uint8_t* new_dst_addr);

        /**
         * \brief Setter for the source's address.
         *
         * \param new_src_addr const uint8_t array of 6 bytes containing the new source's address.
         */
        void src_addr(const uint8_t* new_src_addr);

        /**
         * \brief Setter for the filtering's address.
         *
         * \param new_filter_addr const uint8_t array of 6 bytes containing the new filtering's address.
         */
        void filter_addr(const uint8_t* new_filter_addr);

        /**
         * \brief Setter for the fragment number.
         *
         * \param new_frag_num uint8_t with the new fragment number.
         */
        void frag_num(uint8_t new_frag_num);

        /**
         * \brief Setter for the sequence number.
         *
         * \param new_seq_num uint16_t with the new sequence number.
         */
        void seq_num(uint16_t new_seq_num);

        /**
         * \brief Setter for the optional address.
         *
         * \param new_opt_addr const uint8_t array of 6 bytes containing the new optional address.
         */
        void opt_addr(const uint8_t* new_opt_addr);

        /**
         * \brief Setter for the interface.
         *
         * \param new_iface_index uint32_t containing the new interface index.
         */
        void iface(uint32_t new_iface_index);

        /**
         * \brief Setter for the interface.
         *
         * \param new_iface string reference containing the new interface name.
         */
        void iface(const std::string& new_iface) throw (std::runtime_error);

        /* Virtual methods */
        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \sa PDU::send()
         */
        bool send(PacketSender* sender);

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::IEEE802_11; }
    private:
        /**
         * Struct that represents the 802.11 header
         */
        struct ieee80211_header {
            struct {
            #if __BYTE_ORDER == __LITTLE_ENDIAN
                unsigned int protocol:2;
                unsigned int type:2;
                unsigned int subtype:4;
                unsigned int to_ds:1;
                unsigned int from_ds:1;
                unsigned int more_frag:1;
                unsigned int retry:1;
                unsigned int power_mgmt:1;
                unsigned int more_data:1;
                unsigned int wep:1;
                unsigned int order:1;
            #elif __BYTE_ORDER == __BIG_ENDIAN
                unsigned int protocol:2;
                unsigned int type:2;
                unsigned int subtype:4;
                unsigned int to_ds:1;
                unsigned int from_ds:1;
                unsigned int more_frag:1;
                unsigned int retry:1;
                unsigned int power_mgmt:1;
                unsigned int more_data:1;
                unsigned int wep:1;
                unsigned int order:1;
            #endif
            } __attribute__((__packed__)) control;
            uint16_t duration_id;
            uint8_t dst_addr[6];
            uint8_t src_addr[6];
            uint8_t filter_addr[6];
            struct {
            #if __BYTE_ORDER == __LITTLE_ENDIAN
                unsigned int seq_number:12;
                unsigned int frag_number:4;
            #elif __BYTE_ORDER == __BIG_ENDIAN
                unsigned int frag_number:4;
                unsigned int seq_number:12;
            #endif
            } __attribute__((__packed__)) seq_control;
            uint8_t opt_addr[6];

        } __attribute__((__packed__));

        IEEE802_11(const ieee80211_header *header_ptr);

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        ieee80211_header _header;
        uint32_t _iface_index;
    };

}

#endif
