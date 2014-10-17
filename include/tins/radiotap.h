/*
 * Copyright (c) 2014, Matias Fontanini
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

#include "config.h"

#if !defined(TINS_RADIOTAP_H) && defined(HAVE_DOT11)
#define TINS_RADIOTAP_H

#include "macros.h"
#include "pdu.h"
#include "endianness.h"

namespace Tins {
    class PacketSender;
    
    /** 
     * \brief Class that represents the IEEE 802.11 radio tap header.
     * 
     * By default, RadioTap PDUs set the necesary fields to send an 802.11
     * PDU as its inner pdu, avoiding packet drops. As a consequence, 
     * the FCS-at-end flag is on, the channel is set to 1, TSFT is set to 0,
     * dbm_signal is set to 0xce, and the rx_flag and antenna fields to 0.
     */
    class RadioTap : public PDU {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::RADIOTAP;
    
        /**
         * \brief Enumeration of the different channel type flags.
         * 
         * These channel type flags can be OR'd and set using the
         * RadioTap::channel() method.
         */
        enum ChannelType {
            TURBO   = 0x10,
            CCK     = 0x20,
            OFDM    = 0x40,
            TWO_GZ  = 0x80,
            FIVE_GZ = 0x100,
            PASSIVE = 0x200,
            DYN_CCK_OFDM = 0x400,
            GFSK    = 0x800
        };
        
        /**
         * \brief Flags used in the present field.
         * 
         * \sa RadioTap::present()
         */
        enum PresentFlags {
            TSTF                = 1,
            FLAGS               = 2,
            RATE                = 4,
            CHANNEL             = 8,
            FHSS                = 16,
            DBM_SIGNAL          = 32,
            DBM_NOISE           = 64,
            LOCK_QUALITY        = 128,
            TX_ATTENUATION      = 256,
            DB_TX_ATTENUATION   = 512,
            DBM_TX_ATTENUATION  = 1024,
            ANTENNA             = 2048,
            DB_SIGNAL           = 4096,
            DB_NOISE            = 8192,
            RX_FLAGS            = 16382,
            CHANNEL_PLUS        = 262144
        };
        
        /**
         * \brief Flags used in the RadioTap::flags() method.
         */
        enum FrameFlags {
            CFP           = 1,
            PREAMBLE      = 2,
            WEP           = 4,
            FRAGMENTATION = 8,
            FCS           = 16,
            PADDING       = 32,
            FAILED_FCS    = 64,
            SHORT_GI      = 128
        };
        
        /**
         * \brief Default constructor.
         */
        RadioTap();
        
        /**
         * \brief Constructs a RadioTap object from a buffer and adds all
         * identifiable PDUs found in the buffer as children of this one.
         * 
         * If there is not enough size for a RadioTap header, a
         * malformed_packet exception is thrown.
         * 
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        RadioTap(const uint8_t *buffer, uint32_t total_sz);
        
        /* Setters */
        
        #ifndef WIN32
        /**
         * \sa PDU::send()
         */
        void send(PacketSender &sender, const NetworkInterface &iface);
        #endif
        
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
        void length(uint16_t new_length);
        
        /**
         * \brief Setter for the TSFT field.
         * \param new_tsft The new TSFT
         */
        void tsft(uint64_t new_tsft);
        
        /**
         * \brief Setter for the flags field.
         * \param new_flags The new flags.
         */
        void flags(FrameFlags new_flags);
        
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
         * \brief Setter for the dbm noise field.
         * \param new_dbm_noise The new dbm noise.
         */
        void dbm_noise(uint8_t new_dbm_noise);
        
        /**
         * \brief Setter for the signal quality field.
         * \param new_antenna The signal quality signal.
         */
        void signal_quality(uint8_t new_signal_quality);

        /**
         * \brief Setter for the antenna field.
         * \param new_antenna The antenna signal.
         */
        void antenna(uint8_t new_antenna);
        
        /**
         * \brief Setter for the db signal field.
         * \param new_antenna The db signal signal.
         */
        void db_signal(uint8_t new_db_signal);

        /**
         * \brief Setter for the rx flag field.
         * \param new_rx_flag The antenna signal.
         */
        void rx_flags(uint16_t new_rx_flag);
        
        /* Getters */
        
        /**
         * \brief Getter for the version field.
         * \return The version field.
         */
        uint8_t version() const { return _radio.it_version; }
    
        /**
         * \brief Getter for the padding field.
         * \return The padding field.
         */
        uint8_t padding() const { return _radio.it_pad; }
        
        /**
         * \brief Getter for the length field.
         * \return The length field.
         */
        uint16_t length() const { return Endian::le_to_host(_radio.it_len); }
        
        /**
         * \brief Getter for the tsft field.
         * \return The tsft field.
         */
        uint64_t tsft() const { return Endian::le_to_host(_tsft); }
        
        /**
         * \brief Getter for the flags field.
         * \return The flags field.
         */
        FrameFlags flags() const { return (FrameFlags)_flags; }
        
        /**
         * \brief Getter for the rate field.
         * \return The rate field.
         */
        uint8_t rate() const { return _rate; }
        
        /**
         * \brief Getter for the channel frequency field.
         * \return The channel frequency field.
         */
        uint16_t channel_freq() const { return Endian::le_to_host(_channel_freq); }
        
        /**
         * \brief Getter for the channel type field.
         * \return The channel type field.
         */
        uint16_t channel_type() const { return Endian::le_to_host(_channel_type); }
        
        /**
         * \brief Getter for the dbm signal field.
         * \return The dbm signal field.
         */
        uint8_t dbm_signal() const { return _dbm_signal; }
        
        /**
         * \brief Getter for the dbm noise field.
         * \return The dbm noise field.
         */
        uint8_t dbm_noise() const { return _dbm_noise; }
        
        /**
         * \brief Getter for the signal quality field.
         * \return The signal quality field.
         */
        uint16_t signal_quality() const { return _signal_quality; }

        /**
         * \brief Getter for the antenna field.
         * \return The antenna field.
         */
        uint8_t antenna() const { return _antenna; }

        /**
         * \brief Getter for the db signal field.
         * \return The db signal field.
         */
        uint8_t db_signal() const { return _db_signal; }
        
        /**
         * \brief Getter for the channel+ field.
         * \return The channel+ field.
         */
        uint32_t channel_plus() const { return Endian::le_to_host<uint32_t>(_channel_type); }
        
        /**
         * \brief Getter for the rx flags field.
         * \return The rx flags field.
         */
        uint16_t rx_flags() const { return Endian::le_to_host(_rx_flags); }
        
        /**
         * \brief Getter for the present bit fields.
         * 
         * Use this method and masks created from the values taken from 
         * the PresentFlags enum to find out which fields are set. 
         * Accessing non-initialized fields, the behaviour is undefined
         * will be undefined. It is only safe to use the getter of a field 
         * if its corresponding bit flag is set in the present field.
         */
        PresentFlags present() const { 
            //return (PresentFlags)*(uint32_t*)(&_radio.it_len + 1); 
            return (PresentFlags)Endian::le_to_host(_radio.flags_32);
        }
        
        /** \brief Check wether ptr points to a valid response for this PDU.
         *
         * \sa PDU::matches_response
         * \param ptr The pointer to the buffer.
         * \param total_sz The size of the buffer.
         */
        bool matches_response(const uint8_t *ptr, uint32_t total_sz) const;
        
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
         * \sa PDU::clone
         */
        RadioTap *clone() const {
            return new RadioTap(*this);
        }
        
        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::RADIOTAP; }
    private:
        TINS_BEGIN_PACK
        struct radiotap_hdr {
        #if TINS_IS_LITTLE_ENDIAN
            uint8_t it_version;	
            uint8_t it_pad;
            uint16_t it_len;
            union {
                struct {
                    uint32_t tsft:1,
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
                } flags;
                uint32_t flags_32;
            };
        #else
            uint8_t it_pad;
            uint8_t it_version;	
            uint16_t it_len;
            union {
                struct {
                    uint32_t lock_quality:1,
                        dbm_noise:1,
                        dbm_signal:1,
                        fhss:1,
                        channel:1,
                        rate:1,
                        flags:1,
                        tsft:1,
                        reserved3:1,
                        rx_flags:1,
                        db_tx_attenuation:1,
                        dbm_tx_attenuation:1,
                        antenna:1,
                        db_signal:1,
                        db_noise:1,
                        tx_attenuation:1,
                        reserved2:5,
                        channel_plus:1,
                        reserved1:2,
                        reserved4:7,
                        ext:1;
                } flags;
                uint32_t flags_32;
            };
        #endif
        } TINS_END_PACK;
        
        void init();
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        
        radiotap_hdr _radio;
        // present fields...
        uint64_t _tsft;
        uint16_t _channel_type, _channel_freq, _rx_flags, _signal_quality;
        uint8_t _antenna, _flags, _rate, _dbm_signal, _dbm_noise, _channel, _max_power, _db_signal;
    };
}

#endif // TINS_RADIOTAP_H
