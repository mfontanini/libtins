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

#ifndef TINS_SNAP_H
#define TINS_SNAP_H


#include <stdint.h>
#include "pdu.h"
#include "endianness.h"
#include "small_uint.h"

namespace Tins {

    /**
     * \brief Class representing a SNAP frame.
     * 
     * Note that this PDU contains the 802.3 LLC structure + SNAP frame.
     * So far only unnumbered information structure is supported.
     */
    class SNAP : public PDU {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::SNAP;
    
        /**
         * \brief Creates an instance of SNAP
         * This constructor sets the dsap and ssap fields to 0xaa, and
         * the id field to 3.
         * \param child The child PDU.(optional)
         */
        SNAP(PDU *child = 0);
        
        /**
         * \brief Constructor which creates a SNAP object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        SNAP(const uint8_t *buffer, uint32_t total_sz);
        
        /* Setters */
        
        /**
         * \brief Setter for the control field.
         * \param new_id The new control to be set.
         */
        void control(uint8_t new_control);
        
        /**
         * \brief Setter for the org code field.
         * \param new_org The new org code to be set.
         */
        void org_code(small_uint<24> new_org);
        
        /**
         * \brief Setter for the eth type field.
         * \param new_eth The new eth type to be set.
         */
        void eth_type(uint16_t new_eth);
        
        /* Getters */
        
        /**
         * \brief Getter for the dsap field.
         * \return The dsap field.
         */
        uint8_t dsap() const { return _snap.dsap; }
        
        /**
         * \brief Getter for the ssap field.
         * \return The ssap field.
         */
        uint8_t ssap() const { return _snap.ssap; }
        
        /**
         * \brief Getter for the control field.
         * \return The control field.
         */
        uint8_t control() const { return _snap.control; }
        
        /**
         * \brief Getter for the org code field.
         * \return The org code field.
         */        
        small_uint<24> org_code() const { 
            #ifdef TINS_IS_LITTLE_ENDIAN
                return Endian::be_to_host<uint32_t>(_snap.org_code << 8); 
            #else
                return Endian::be_to_host(_snap.org_code); 
            #endif
        }
        
        /**
         * \brief Getter for the eth type field.
         * \return The eth field.
         */
        uint16_t eth_type() const { return Endian::be_to_host(_snap.eth_type); } 
        
        /**
         * \brief Returns the SNAP frame's header length.
         *
         * \return The header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
        
        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::SNAP; }
        
        /**
         * \brief Clones this PDU.
         * 
         * \sa PDU::clone_pdu
         */
        SNAP *clone_pdu() const {
            return new SNAP(*this);
        }    
    private:
        struct snaphdr {
            uint8_t dsap;
            uint8_t ssap;
            #if TINS_IS_LITTLE_ENDIAN
                uint32_t control:8,
                        org_code:24;
            #elif TINS_IS_BIG_ENDIAN
                uint32_t org_code:24,
                        control:8;
            #endif
            uint16_t eth_type;
        } __attribute__((__packed__));
        
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        snaphdr _snap;
    };
    
};

#endif // TINS_SNAP_H
