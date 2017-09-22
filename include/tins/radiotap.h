/*
 * Copyright (c) 2017, Matias Fontanini
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

#include <tins/config.h>

#if !defined(TINS_RADIOTAP_H) && defined(TINS_HAVE_DOT11)
#define TINS_RADIOTAP_H

#include <tins/macros.h>
#include <tins/pdu.h>
#include <tins/endianness.h>
#include <tins/pdu_option.h>

namespace Tins {
class PacketSender;

/** 
 * \brief Class that represents the IEEE 802.11 radio tap header.
 * 
 * By default, RadioTap PDUs set the necesary fields to send an 802.11
 * PDU as its inner pdu, avoiding packet drops. As a consequence, 
 * the FCS-at-end flag is on, the channel is set to 1, TSFT is set to 0,
 * dbm_signal is set to -50, and the rx_flag and antenna fields to 0.
 */
class TINS_API RadioTap : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::RADIOTAP;

    /**
     * RadioTap is little endian
     */
    static const endian_type endianness = LE;

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
        TSFT                = 1 << 0,
        TSTF                = 1 << 0, ///< Deprecated (typo), use TSFT
        FLAGS               = 1 << 1,
        RATE                = 1 << 2,
        CHANNEL             = 1 << 3,
        FHSS                = 1 << 4,
        DBM_SIGNAL          = 1 << 5,
        DBM_NOISE           = 1 << 6,
        LOCK_QUALITY        = 1 << 7,
        TX_ATTENUATION      = 1 << 8,
        DB_TX_ATTENUATION   = 1 << 9,
        DBM_TX_ATTENUATION  = 1 << 10,
        ANTENNA             = 1 << 11,
        DB_SIGNAL           = 1 << 12,
        DB_NOISE            = 1 << 13,
        RX_FLAGS            = 1 << 14,
        TX_FLAGS            = 1 << 15,
        DATA_RETRIES        = 1 << 17,
        XCHANNEL            = 1 << 18,
        CHANNEL_PLUS        = 1 << 18,
        MCS                 = 1 << 19
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
     * \brief The type used to represent the MCS flags field
     */
    TINS_BEGIN_PACK
    struct mcs_type {
        uint8_t known;
        uint8_t flags;
        uint8_t mcs;
    } TINS_END_PACK;

    /**
     * \brief The type used to represent the XChannel field
     */
    TINS_BEGIN_PACK
    struct xchannel_type {
        uint32_t flags;
        uint16_t frequency;
        uint8_t channel;
        uint8_t max_power;
    } TINS_END_PACK;
    
    /**
     * The type used to store RadioTap options
     */
    typedef PDUOption<RadioTap::PresentFlags, RadioTap> option;

    /**
     * The type used to store the options payload
     */
    typedef std::vector<uint8_t> options_payload_type;

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
    RadioTap(const uint8_t* buffer, uint32_t total_sz);
    
    /* Setters */
    
    #ifndef _WIN32
    /**
     * \sa PDU::send()
     */
    void send(PacketSender& sender, const NetworkInterface& iface);
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
    void dbm_signal(int8_t new_dbm_signal);
    
    /**
     * \brief Setter for the dbm noise field.
     * \param new_dbm_noise The new dbm noise.
     */
    void dbm_noise(int8_t new_dbm_noise);
    
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
     * \param new_rx_flag The rx flags.
     */
    void rx_flags(uint16_t new_rx_flag);

    /**
     * \brief Setter for the tx flag field.
     * \param new_tx_flag The tx flags.
     */
    void tx_flags(uint16_t new_tx_flag);

    /**
     * \brief Setter for the xchannel field.
     * \param new_xchannel The xchannel field
     */
    void xchannel(xchannel_type new_xchannel);

    /**
     * \brief Setter for the data retries field.
     * \param new_rx_flag The data retries.
     */
    void data_retries(uint8_t new_data_retries);

    /**
     * \brief Setter for the MCS field.
     * \param new_rx_flag The MCS retries.
     */
    void mcs(const mcs_type& new_mcs);
    
    /* Getters */
    
    /**
     * \brief Getter for the version field.
     * \return The version field.
     */
    uint8_t version() const;

    /**
     * \brief Getter for the padding field.
     * \return The padding field.
     */
    uint8_t padding() const;
    
    /**
     * \brief Getter for the length field.
     * \return The length field.
     */
    uint16_t length() const;
    
    /**
     * \brief Getter for the tsft field.
     * \return The tsft field.
     */
    uint64_t tsft() const;
    
    /**
     * \brief Getter for the flags field.
     * \return The flags field.
     */
    FrameFlags flags() const;
    
    /**
     * \brief Getter for the rate field.
     * \return The rate field.
     */
    uint8_t rate() const;
    
    /**
     * \brief Getter for the channel frequency field.
     * \return The channel frequency field.
     */
    uint16_t channel_freq() const;
    
    /**
     * \brief Getter for the channel type field.
     * \return The channel type field.
     */
    uint16_t channel_type() const;
    
    /**
     * \brief Getter for the dbm signal field.
     * \return The dbm signal field.
     */
    int8_t dbm_signal() const;
    
    /**
     * \brief Getter for the dbm noise field.
     * \return The dbm noise field.
     */
    int8_t dbm_noise() const;
    
    /**
     * \brief Getter for the signal quality field.
     * \return The signal quality field.
     */
    uint16_t signal_quality() const;

    /**
     * \brief Getter for the antenna field.
     * \return The antenna field.
     */
    uint8_t antenna() const;

    /**
     * \brief Getter for the db signal field.
     * \return The db signal field.
     */
    uint8_t db_signal() const;
    
    /**
     * \brief Getter for the XChannel field.
     * \return The XChannel field.
     */
    xchannel_type xchannel() const;
    
    /**
     * \brief Getter for the data retries field
     * \return The data retries field.
     */
    uint8_t data_retries() const;

    /**
     * \brief Getter for the rx flags field.
     * \return The rx flags field.
     */
    uint16_t rx_flags() const;

    /**
     * \brief Getter for the tx flags field.
     * \return The tx flags field.
     */
    uint16_t tx_flags() const;
    
    /**
     * \brief Getter for the MCS field.
     * \return The MCS field.
     */
    mcs_type mcs() const;

    /**
     * \brief Getter for the present bit fields.
     * 
     * Use this method and masks created from the values taken from 
     * the PresentFlags enum to find out which fields are set. 
     * Accessing non-initialized fields, the behaviour is undefined
     * will be undefined. It is only safe to use the getter of a field 
     * if its corresponding bit flag is set in the present field.
     */
    PresentFlags present() const;
    
    /** \brief Check whether ptr points to a valid response for this PDU.
     *
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const;
    
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
     * Adds the given option
     *
     * \param option The option to be added.
     */
    void add_option(const option& opt);

    /**
     * \brief Gets the options payload
     *
     * Use Utils::RadioTapParser to iterate these options and extract fields manually,
     * in case you want to have deeper access into the option types/values stored in 
     * a RadioTap frame.
     */
    const options_payload_type& options_payload() const;

    /**
     * \sa PDU::clone
     */
    RadioTap* clone() const {
        return new RadioTap(*this);
    }
    
    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }
private:
    TINS_BEGIN_PACK
    struct radiotap_header {
    #if TINS_IS_LITTLE_ENDIAN
        uint8_t it_version;	
        uint8_t it_pad;
    #else
        uint8_t it_pad;
        uint8_t it_version;
    #endif // TINS_IS_LITTLE_ENDIAN 
        uint16_t it_len;
    } TINS_END_PACK;
    
    void write_serialization(uint8_t* buffer, uint32_t total_sz);
    option do_find_option(PresentFlags type) const;

    radiotap_header header_;
    options_payload_type options_payload_;
};
}

#endif // TINS_RADIOTAP_H
