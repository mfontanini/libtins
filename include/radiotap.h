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
    class RadioTap : public PDU {
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
        
        /* Setters */
        
        /**
         * \sa PDU::send()
         */
        bool send(PacketSender* sender);
        
        /**
         * \brief Setter for the version field.
         * \param new_version The new version.
         */
        void version(uint8_t new_version);
        
        /**
         * \brief Setter for the padding field.
         * \param new_padding The new padding.
         */
        void padding(uint8_t new_padding);
        
        /**
         * \brief Setter for the length field.
         * \param new_length The new length.
         */
        void length(uint8_t new_length);
        
        /**
         * \brief Setter for the TSFT field.
         * \param new_tsft The new TSFT
         */
        void tsft(uint64_t new_tsft);
        
        /**
         * \brief Setter for the flags field.
         * \param new_flags The new flags.
         */
        void flags(uint8_t new_flags);
        
        /**
         * \brief Setter for the rate field.
         * \param new_rate The new rate.
         */
        void rate(uint8_t new_rate);
        
        /**
         * \brief Setter for the channel frequency and type field.
         * \param new_freq The new channel frequency.
         * \param new_type The new channel type.
         */
        void channel(uint16_t new_freq, uint16_t new_type);
        
        /**
         * \brief Setter for the dbm signal field.
         * \param new_dbm_signal The new dbm signal.
         */
        void dbm_signal(uint8_t new_dbm_signal);
        
        /**
         * \brief Setter for the antenna field.
         * \param new_antenna The antenna signal.
         */
        void antenna(uint8_t new_antenna);
        
        /**
         * \brief Setter for the rx flag field.
         * \param new_rx_flag The antenna signal.
         */
        void rx_flag(uint16_t new_rx_flag);
        
        /* Getters */
        
        /**
         * \brief Getter for the version field.
         * \return The version field.
         */
        inline uint8_t version() const { return _radio.it_version; }
    
        /**
         * \brief Getter for the padding field.
         * \return The padding field.
         */
        inline uint8_t padding() const { return _radio.it_pad; }
        
        /**
         * \brief Getter for the length field.
         * \return The length field.
         */
        inline uint8_t length() const { return _radio.it_len; }
        
        /**
         * \brief Getter for the tsft field.
         * \return The tsft field.
         */
        inline uint64_t tsft() const { return _tsft; }
        
        /**
         * \brief Getter for the flags field.
         * \return The flags field.
         */
        inline uint8_t flags() const { return _flags; }
        
        /**
         * \brief Getter for the rate field.
         * \return The rate field.
         */
        inline uint8_t rate() const { return _rate; }
        
        /**
         * \brief Getter for the channel frequency field.
         * \return The channel frequency field.
         */
        inline uint16_t channel_freq() const { return _channel_freq; }
        
        /**
         * \brief Getter for the channel type field.
         * \return The channel type field.
         */
        inline uint16_t channel_type() const { return _channel_type; }
        
        /**
         * \brief Getter for the dbm signal field.
         * \return The dbm signal field.
         */
        inline uint8_t dbm_signal() const { return _dbm_signal; }
        
        /**
         * \brief Getter for the antenna field.
         * \return The antenna field.
         */
        inline uint8_t antenna() const { return _antenna; }
        
        /**
         * \brief Getter for the rx flags field.
         * \return The rx flags field.
         */
        inline uint16_t rx_flags() const { return _rx_flags; }
        
        
        /**
         * \brief Returns the RadioTap frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
        
        /**
         * \brief Returns the frame's trailer size.
         * \return The trailer's size.
         */
        uint32_t trailer_size() const;
        
        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::RADIOTAP; }
    private:
        struct radiotap_hdr {
            u_int8_t it_version;	
            u_int8_t it_pad;
            u_int16_t it_len;
            u_int32_t tsft:1,
                flags:1,
                rate:1,
                channel:1,
                fhss:1,
                dbm_signal:1,
                dbm_noise:1,
                lock_quality:1,
                tx_attenuation:1,
                db_tx_attenuation:1,
                dbm_tx_attenuation:1,
                antenna:1,
                db_signal:1,
                db_noise:1,
                rx_flags:1,
                reserved1:3,
                channel_plus:1,
                reserved2:12,
                ext:1;
        } __attribute__((__packed__));
        
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        radiotap_hdr _radio;
        uint32_t _iface_index, _options_size;
        // present fields...
        uint64_t _tsft;
        uint8_t _flags, _rate;
        uint16_t _channel_freq, _channel_type;
        uint8_t _dbm_signal;
        uint8_t _antenna;
        uint16_t _rx_flags;
    };
};
#endif
