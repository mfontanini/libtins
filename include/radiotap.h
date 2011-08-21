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

#ifndef __RADIOTAP_H
#define __RADIOTAP_H

#include <stdexcept>
#include "pdu.h"

namespace Tins {
    
    /** 
     * \brief Class that represents the IEEE 802.11 radio tap header.
     */
    class RadioTap {
    public:
        /**
         * Creates an instance of RadioTap.
         * \param iface The name of the interface in which to send this PDU.
         */
        RadioTap(const std::string &iface) throw (std::runtime_error);
        
        /**
         * Creates an instance of RadioTap.
         * \param iface_index The index of the interface in which to send this PDU.
         */
        RadioTap(uint32_t iface_index);
        
        /**
         * \sa PDU::send()
         */
        bool send(PacketSender* sender);
        
        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
    private:
        struct radiotap_hdr {
            u_int8_t it_version;	
            u_int8_t it_pad;
            u_int16_t it_len;
            u_int32_t it_present;
        } __attribute__((__packed__));
        
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        radiotap_hdr _radio;
        uint32_t _iface_index;
    };
};
#endif
