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

#ifndef TINS_IEEE8022_H
#define TINS_IEEE8022_H


#include <stdint.h>
#include "pdu.h"
#include "utils.h"

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
        
        /**
         * \brief Copy constructor.
         */
        SNAP(const SNAP &other);
        
        /**
         * \brief Copy assignment operator.
         */
        SNAP &operator= (const SNAP &other);
        
        /* Setters */
        
        /**
         * \brief Setter for the id field.
         * \param new_id The new id to be set.
         */
        void id(uint8_t new_id);
        
        /**
         * \brief Setter for the poll field.
         * \param new_poll The new poll to be set.
         */
        void poll(uint8_t new_poll);
        
        /**
         * \brief Setter for the org code field.
         * \param new_org The new org code to be set.
         */
        void org_code(uint32_t new_org);
        
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
         * \brief Getter for the id field.
         * \return The id field.
         */
        uint8_t id() const { return _snap.id; }
        
        /**
         * \brief Getter for the poll field.
         * \return The poll field.
         */
        uint8_t poll() const { return _snap.poll; }
        
        /**
         * \brief Getter for the org code field.
         * \return The org code field.
         */
        uint32_t org_code() const { return _snap.org_code; }
        
        /**
         * \brief Getter for the eth type field.
         * \return The eth field.
         */
        uint16_t eth_type() const { return Utils::be_to_host(_snap.eth_type); }
        
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
        PDU *clone_pdu() const;
    private:
        struct snaphdr {
            uint8_t dsap;
            uint8_t ssap;
            #if TINS_IS_LITTLE_ENDIAN
                uint32_t id:2,
                    reserved1:2,
                    poll:2,
                    reserved2:2,
                    org_code:24;
            #elif TINS_IS_BIG_ENDIAN
                uint32_t reserved1:2,
                    poll:2,
                    reserved2:2,
                    id:2,
                    org_code:24;
            #endif
            uint16_t eth_type;
        } __attribute__((__packed__));
        
        void copy_fields(const SNAP *other);
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        snaphdr _snap;
    };
    
};

#endif // TINS_IEEE8022_H
