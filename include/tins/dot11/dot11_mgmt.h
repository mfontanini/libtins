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

#if !defined(TINS_DOT11_DOT11_MGMT_H) && defined(TINS_HAVE_DOT11)

#define TINS_DOT11_DOT11_MGMT_H

#include <vector>
#include <utility>
#include <tins/dot11/dot11_base.h>
#include <tins/macros.h>

namespace Tins {
/**
 * \brief Base class for all management frames in the IEEE 802.11 protocol.
 */
class TINS_API Dot11ManagementFrame : public Dot11 {
public:
    /**
     * The supported rates container type.
     */
    typedef std::vector<float> rates_type;
    
    /**
     * The supported channels container type.
     */
    typedef std::vector<std::pair<uint8_t, uint8_t> > channels_type;

    /**
     * The channel map container type.
     */
    typedef std::vector<std::pair<uint8_t, uint8_t> > channel_map_type;

    /**
     * The requested information container type.
     */
    typedef std::vector<uint8_t> request_info_type;

    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_MANAGEMENT;

    /**
     * \brief Enum used in the reason code field.
     *
     * This enumeration can be used to get or set the reason code field in a
     * Deauthentication or Disassociation
     */
    enum ReasonCodes {
        UNSPECIFIED = 1,
        PREV_AUTH_NOT_VALID = 2,
        STA_LEAVING_IBSS_ESS = 3,
        INACTIVITY = 4,
        CANT_HANDLE_STA = 5,
        CLASS2_FROM_NO_AUTH = 6,
        CLASS3_FROM_NO_AUTH = 7,
        STA_LEAVING_BSS = 8,
        STA_NOT_AUTH_WITH_STA = 9,
        POW_CAP_NOT_VALID = 10,
        SUPPORTED_CHANN_NOT_VALID = 11,
        INVALID_CONTENT = 13,
        MIC_FAIL = 14,
        HANDSHAKE_TIMEOUT = 15,
        GROUP_KEY_TIMEOUT = 16,
        WRONG_HANDSHAKE = 17,
        INVALID_GROUP_CIPHER = 18,
        INVALID_PAIRWISE_CIPHER = 19,
        INVALID_AKMP = 20,
        UNSOPPORTED_RSN_VERSION = 21,
        INVALID_RSN_CAPABILITIES = 22,
        AUTH_FAILED = 23,
        CIPHER_SUITE_REJECTED = 24,
        UNSPECIFIED_QOS_REASON = 32,
        NOT_ENOUGH_BANDWITH = 33,
        POOR_CHANNEL = 34,
        STA_OUT_OF_LIMITS = 35,
        REQUESTED_BY_STA_LEAVING = 36,
        REQUESTED_BY_STA_REJECT_MECHANISM = 37,
        REQUESTED_BY_STA_REJECT_SETUP = 38,
        REQUESTED_BY_STA_TIMEOUT = 39,
        PEER_STA_NOT_SUPPORT_CIPHER = 45
    };

    /**
     * \brief Enum that represents the map field within a channels map field.
     *
     * These bitmasks can be used to get or set the second value of
     * ibss_dfs_params().channel_map
     */
    enum MapMask {
        BSS                 = 0x1,
        OFDM_PREAMBLE       = 0x2,
        UNIDENTIFIED_SIGNAL = 0x4,
        RADAR               = 0x8,
        UNMEASURED          = 0x10,
        RESERVED            = 0xE0
    };
    
    /**
     * Represents the IEEE 802.11 frames' capability information.
     */
    TINS_BEGIN_PACK
    class capability_information {
    private:
        #if TINS_IS_LITTLE_ENDIAN
            uint16_t ess_:1,
                     ibss_:1,
                     cf_poll_:1,
                     cf_poll_req_:1,
                     privacy_:1,
                     short_preamble_:1,
                     pbcc_:1,
                     channel_agility_:1,
                     spectrum_mgmt_:1,
                     qos_:1,
                     sst_:1,
                     apsd_:1,
                     radio_measurement_:1,
                     dsss_ofdm_:1,
                     delayed_block_ack_:1,
                     immediate_block_ack_:1;
        #elif TINS_IS_BIG_ENDIAN
            uint16_t channel_agility_:1,
                     pbcc_:1,
                     short_preamble_:1,
                     privacy_:1,
                     cf_poll_req_:1,
                     cf_poll_:1,
                     ibss_:1,
                     ess_:1,
                     immediate_block_ack_:1,
                     delayed_block_ack_:1,
                     dsss_ofdm_:1,
                     radio_measurement_:1,
                     apsd_:1,
                     sst_:1,
                     qos_:1,
                     spectrum_mgmt_:1;
        #endif
    public:
        /**
         * \brief Getter for the ess flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool ess() const {
            return ess_;
        }

        /**
         * \brief Getter for the ibss flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool ibss() const {
            return ibss_;
        }

        /**
         * \brief Getter for the cf_poll flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool cf_poll() const {
            return cf_poll_;
        }

        /**
         * \brief Getter for the cf_poll_req flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool cf_poll_req() const {
            return cf_poll_req_;
        }

        /**
         * \brief Getter for the privacy flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool privacy() const {
            return privacy_;
        }

        /**
         * \brief Getter for the short_preamble flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool short_preamble() const {
            return short_preamble_;
        }

        /**
         * \brief Getter for the pbcc flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool pbcc() const {
            return pbcc_;
        }

        /**
         * \brief Getter for the channel_agility flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool channel_agility() const {
            return channel_agility_;
        }

        /**
         * \brief Getter for the spectrum_mgmt flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool spectrum_mgmt() const {
            return spectrum_mgmt_;
        }

        /**
         * \brief Getter for the qos flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool qos() const {
            return qos_;
        }

        /**
         * \brief Getter for the sst flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool sst() const {
            return sst_;
        }

        /**
         * \brief Getter for the apsd flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool apsd() const {
            return apsd_;
        }

        /**
         * \brief Getter for the radio measurement flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool radio_measurement() const {
            return radio_measurement_;
        }

        /**
         * \brief Getter for the dsss_ofdm flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool dsss_ofdm() const {
            return dsss_ofdm_;
        }

        /**
         * \brief Getter for the delayed_block_ack flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool delayed_block_ack() const {
            return delayed_block_ack_;
        }

        /**
         * \brief Getter for the immediate_block_ack flag.
         *
         * \return Bool indicating the flag's value.
         */
        bool immediate_block_ack() const {
            return immediate_block_ack_;
        }

        /**
         * \brief Setter for the ess flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void ess(bool new_value) {
            ess_ = new_value;
        }

        /**
         * \brief Setter for the ibss flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void ibss(bool new_value) {
            ibss_ = new_value;
        }

        /**
         * \brief Setter for the cf_poll flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void cf_poll(bool new_value) {
            cf_poll_ = new_value;
        }

        /**
         * \brief Setter for the cf_poll_req flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void cf_poll_req(bool new_value) {
            cf_poll_req_ = new_value;
        }

        /**
         * \brief Setter for the privacy flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void privacy(bool new_value) {
            privacy_ = new_value;
        }

        /**
         * \brief Setter for the short_preamble flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void short_preamble(bool new_value) {
            short_preamble_ = new_value;
        }

        /**
         * \brief Setter for the pbcc flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void pbcc(bool new_value) {
            pbcc_ = new_value;
        }

        /**
         * \brief Setter for the channel_agility flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void channel_agility(bool new_value) {
            channel_agility_ = new_value;
        }

        /**
         * \brief Setter for the spectrum_mgmt flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void spectrum_mgmt(bool new_value) {
            spectrum_mgmt_ = new_value;
        }

        /**
         * \brief Setter for the qos flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void qos(bool new_value) {
            qos_ = new_value;
        }

        /**
         * \brief Setter for the sst flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void sst(bool new_value) {
            sst_ = new_value;
        }

        /**
         * \brief Setter for the apsd flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void apsd(bool new_value) {
            apsd_ = new_value;
        }

        /**
         * \brief Setter for the radio measurement flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void radio_measurement(bool new_value) {
            radio_measurement_ = new_value;
        }

        /**
         * \brief Setter for the dsss_ofdm flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void dsss_ofdm(bool new_value) {
            dsss_ofdm_ = new_value;
        }

        /**
         * \brief Setter for the delayed_block_ack flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void delayed_block_ack(bool new_value) {
            delayed_block_ack_ = new_value;
        }

        /**
         * \brief Setter for the immediate_block_ack flag.
         *
         * \param new_value bool indicating the flag's new value.
         */
        void immediate_block_ack(bool new_value) {
            immediate_block_ack_ = new_value;
        }
    } TINS_END_PACK;
    
    /**
     * The type used to store the FS parameters set option data.
     */
    struct fh_params_set {
        uint16_t dwell_time;
        uint8_t hop_set, hop_pattern, hop_index;
        
        fh_params_set()
        : dwell_time(0), hop_set(0), hop_pattern(0), hop_index(0) {}
        
        fh_params_set(uint16_t dwell_time, 
                      uint8_t hop_set, 
                      uint8_t hop_pattern,
                      uint8_t hop_index) 
        : dwell_time(dwell_time), hop_set(hop_set), 
          hop_pattern(hop_pattern), hop_index(hop_index) {}

        static fh_params_set from_option(const option& opt);
    };
    
    /**
     * The type used to store the CF parameters set option data.
     */
    struct cf_params_set {
        uint8_t cfp_count, cfp_period;
        uint16_t cfp_max_duration, cfp_dur_remaining;
        
        cf_params_set()
        : cfp_count(0), cfp_period(0), cfp_max_duration(0), cfp_dur_remaining(0) {}
        
        cf_params_set(uint8_t cfp_count, 
                      uint8_t cfp_period,
                      uint16_t cfp_max_duration,
                      uint16_t cfp_dur_remaining) 
        : cfp_count(cfp_count), cfp_period(cfp_period), 
          cfp_max_duration(cfp_max_duration), 
          cfp_dur_remaining(cfp_dur_remaining) {}

        static cf_params_set from_option(const option& opt);
    };
    
    /**
     * The type used to store the IBSS DFS parameters option data.
     */
    struct ibss_dfs_params {
        static const size_t minimum_size = address_type::address_size + sizeof(uint8_t) + 2 * sizeof(uint8_t);
        
        address_type dfs_owner;
        uint8_t recovery_interval; 
        channel_map_type channel_map;
       
        ibss_dfs_params() : recovery_interval(0) {}
       
        ibss_dfs_params(const address_type& addr, 
                        uint8_t recovery_interval,
                        const channel_map_type& channel_map)
        : dfs_owner(addr), recovery_interval(recovery_interval),
          channel_map(channel_map) {}

        static ibss_dfs_params from_option(const option& opt);
    };
    
    /**
     * The type used to store the Country parameters option data.
     */
    struct country_params {
        // String identifier: 3 bytes
        static const size_t minimum_size = 3 + sizeof(uint8_t) * 3;
        
        std::string country;
        byte_array first_channel, number_channels, max_transmit_power;
        
        country_params() {}
        
        country_params(const std::string& country, 
                       const byte_array& first,
                       const byte_array& number,
                       const byte_array& max) 
        : country(country), first_channel(first), number_channels(number),
          max_transmit_power(max) {}

        static country_params from_option(const option& opt);
    };
    
    /**
     * The type used to store the FH pattern option data.
     */
    struct fh_pattern_type {
        static const size_t minimum_size = sizeof(uint8_t) * 4;
        
        uint8_t flag, number_of_sets, modulus, offset;
        byte_array random_table;
        
        fh_pattern_type()
        : flag(0), number_of_sets(0), modulus(0), offset(0) {}
        
        fh_pattern_type(uint8_t flag, 
                        uint8_t sets,
                        uint8_t modulus,
                        uint8_t offset,
                        const byte_array& table) 
        : flag(flag), number_of_sets(sets), modulus(modulus), 
          offset(offset), random_table(table) {}

        static fh_pattern_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the Channel Switch option data.
     */
    struct channel_switch_type {
        uint8_t switch_mode, new_channel, switch_count;
        
        channel_switch_type()
        : switch_mode(0), new_channel(0), switch_count(0) {}
        
        channel_switch_type(uint8_t mode, 
                            uint8_t channel,
                            uint8_t count)
        : switch_mode(mode), new_channel(channel), switch_count(count) { }

        static channel_switch_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the Quiet option data.
     */
    struct quiet_type {
        uint8_t quiet_count, quiet_period;
        uint16_t quiet_duration, quiet_offset;
        
        quiet_type() 
        : quiet_count(0), quiet_period(0), quiet_duration(0), quiet_offset(0) {}
        
        quiet_type(uint8_t count, 
                   uint8_t period,
                   uint16_t duration,
                   uint16_t offset)
        : quiet_count(count), quiet_period(period), 
        quiet_duration(duration), quiet_offset(offset) {}

        static quiet_type from_option(const option& opt);
    };

    /**
     * The type used to store the BSS Load option data.
     */
    struct bss_load_type {
        uint16_t station_count;
        uint16_t available_capacity;
        uint8_t channel_utilization;
        
        bss_load_type() 
        : station_count(0), available_capacity(0), channel_utilization(0) {}
        
        bss_load_type(uint16_t count, uint8_t utilization, uint16_t capacity) 
        : station_count(count), available_capacity(capacity),
        channel_utilization(utilization) {}

        static bss_load_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the TIM option data.
     */
    struct tim_type {
        uint8_t dtim_count, dtim_period, bitmap_control;
        byte_array partial_virtual_bitmap;
        
        tim_type()
        : dtim_count(0), dtim_period(0), bitmap_control(0) {}
        
        tim_type(uint8_t count, 
                 uint8_t period,
                 uint8_t control,
                 const byte_array& bitmap) 
        : dtim_count(count), dtim_period(period), bitmap_control(control),
        partial_virtual_bitmap(bitmap) {}

        static tim_type from_option(const option& opt);
    };

    /**
     * The type used to store the HT capabilities data.
     */
    struct ht_capability_type {
        uint8_t ampdu_param, asel_capabilities;
        uint16_t capabilities, ext_capabilities;
        uint32_t transmit_beamforing_capabilities;
        uint32_t mcs_rx;
        uint32_t mcs_tx;
        
        ht_capability_type()
        : ampdu_param(0), asel_capabilities(0), capabilities(0), ext_capabilities(0), transmit_beamforing_capabilities(0),
        mcs_rx(0), mcs_tx(0) {}
        
        ht_capability_type(uint16_t capabilities, 
                 uint8_t ampdu_param,
                 uint32_t mcs_rx, uint32_t mcs_tx,
                 uint16_t ext_capabilities,
                 uint32_t transmit_beamforing_capabilities,
                 uint8_t asel_capabilities) 
        : ampdu_param(ampdu_param), asel_capabilities(asel_capabilities), capabilities(capabilities), 
        ext_capabilities(ext_capabilities), transmit_beamforing_capabilities(transmit_beamforing_capabilities),
        mcs_rx(mcs_rx), mcs_tx(mcs_tx) {}

        static ht_capability_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the extended capabilities option data.
     */
    struct ext_capability_type {
        byte_array capabilities;
        
        ext_capability_type()
        {}
        
        ext_capability_type(const byte_array& capabilities) 
        : capabilities(capabilities) {}

        static ext_capability_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the VHT capabilities option data.
     */
    struct vht_capability_type {
        uint32_t capabilities, mcs_rx, mcs_tx;
        
        vht_capability_type()
        : capabilities(0), mcs_rx(0), mcs_tx(0) {}
        
        vht_capability_type(uint32_t capabilities, 
                 uint32_t mcs_rx,
                 uint32_t mcs_tx) 
        : capabilities(capabilities), mcs_rx(mcs_rx), mcs_tx(mcs_tx) {}

        static vht_capability_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the Vendor Specific option data.
     */
    struct vendor_specific_type {
        typedef HWAddress<3> oui_type;

        oui_type oui;
        byte_array data;

        vendor_specific_type(const oui_type& oui = oui_type(),
                             const byte_array& data = byte_array())
        : oui(oui), data(data) { }

        static vendor_specific_type from_bytes(const uint8_t* buffer, uint32_t sz);
    };
    
    /**
     * The type used to store the QOS capability tagged option data.
     */
    typedef uint8_t qos_capability_type;

    /**
     * \brief Getter for the second address.
     *
     * \return address_type containing the second address.
     */
    address_type addr2() const {
        return ext_header_.addr2;
    }

    /**
     * \brief Getter for the third address.
     *
     * \return address_type containing the third address.
     */
    address_type addr3() const {
        return ext_header_.addr3;
    }

    /**
     * \brief Getter for the fragment number.
     *
     * \return The stored fragment number.
     */
    small_uint<4> frag_num() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return ext_header_.frag_seq & 0xf; 
        #else
        return (ext_header_.frag_seq >> 8) & 0xf; 
        #endif
    }

    /**
     * \brief Getter for the sequence number field.
     *
     * \return The stored sequence number.
     */
    small_uint<12> seq_num() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return (ext_header_.frag_seq >> 4) & 0xfff; 
        #else
        return (Endian::le_to_host<uint16_t>(ext_header_.frag_seq) >> 4) & 0xfff; 
        #endif
    }

    /**
     * \brief Getter for the fourth address.
     *
     * \return The stored fourth address.
     */
    const address_type& addr4() const {
        return addr4_;
    }

    /**
     * \brief Setter for the second address.
     *
     * \param new_addr2 The new second address to be set.
     */
    void addr2(const address_type& new_addr2);

    /**
     * \brief Setter for the third address.
     *
     * \param new_addr3 The new third address to be set.
     */
    void addr3(const address_type& new_addr3);

    /**
     * \brief Setter for the fragment number.
     *
     * \param new_frag_num The new fragment number.
     */
    void frag_num(small_uint<4> new_frag_num);

    /**
     * \brief Setter for the sequence number.
     *
     * \param new_seq_num The new sequence number.
     */
    void seq_num(small_uint<12> new_seq_num);

    /**
     * \brief Setter for the fourth address.
     *
     * \param new_addr4 The new fourth address to be set.
     */
    void addr4(const address_type& new_addr4);

    // Option setter helpers

    /**
     * \brief Helper method to set the SSID.
     *
     * \param new_ssid The SSID to be set.
     */
    void ssid(const std::string& new_ssid);

    /**
     * \brief Helper method to set the RSN information option.
     *
     * \param info The RSNInformation structure to be set.
     */
    void rsn_information(const RSNInformation& info);

    /**
     * \brief Helper method to set the supported rates option.
     *
     * \param new_rates The new rates to be set.
     */
    void supported_rates(const rates_type& new_rates);

    /**
     * \brief Helper method to set the extended supported rates option.
     *
     * \param new_rates The new rates to be set.
     */
    void extended_supported_rates(const rates_type& new_rates);

    /**
     * \brief Helper method to set the QoS capabilities option.
     *
     * \param new_qos_capabilities uint8_t with the capabilities.
     */
    void qos_capability(qos_capability_type new_qos_capability);

    /**
     * \brief Helper method to set the power capabilities option.
     *
     * \param min_power uint8_t indicating the minimum transmiting power capability.
     * \param max_power uint8_t indicating the maximum transmiting power capability.
     */
    void power_capability(uint8_t min_power, uint8_t max_power);

    /**
     * \brief Helper method to set the supported channels option.
     * 
     * Each element in the provided vector should be a tuple 
     * (First channel number, number of channels), as defined in the
     * standard.
     *
     * \param new_channels A list of channels to be set.
     */
    void supported_channels(const channels_type& new_channels);

    /**
     * \brief Helper method to set the EDCA Parameter Set.
     *
     * \param ac_be uint32_t with the value of the ac_be field.
     * \param ac_bk uint32_t with the value of the ac_bk field.
     * \param ac_vi uint32_t with the value of the ac_vi field.
     * \param ac_vo uint32_t with the value of the ac_vo field.
     */
    void edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo);

    /**
     * \brief Helper method to set the Request Information element tagged option.
     *
     * \param elements The new list of elements.
     */
    void request_information(const request_info_type elements);

    /**
     * \brief Helper method to set the FH parameter set tagged option.
     *
     * \param fh_params The new FH parameter set value.
     */
    void fh_parameter_set(const fh_params_set& fh_params);

    /**
     * \brief Helper method to set the DS parameter tagged option.
     *
     * \param current_channel The access point's new current channel.
     */
    void ds_parameter_set(uint8_t current_channel);

    /**
     * \brief Helper method to set the CF parameter set tagged option.
     *
     * \param params The new CF parameter set value.
     */
    void cf_parameter_set(const cf_params_set& params);

    /**
     * \brief Helper method to set the IBSS parameter set tagged option.
     *
     * \param atim_window uint16_t with the value of the ATIM window field.
     */
    void ibss_parameter_set(uint16_t atim_window);

    /**
     * \brief Helper method to set the IBSS DFS tagged option.
     *
     * \param params The IBSS DFS data to be set.
     */
    void ibss_dfs(const ibss_dfs_params& params);

    /**
     * \brief Helper method to set the country tagged option.
     *
     * \param params The data to be used for this country option.
     */
    void country(const country_params& params);

    /**
     * \brief Helper method to set the FH parameters set tagged option.
     *
     * \param prime_radix The value of the prime radix field.
     * \param number_channels The value of the number channels field.
     */
    void fh_parameters(uint8_t prime_radix, uint8_t number_channels);

    /**
     * \brief Helper method to set the FH pattern table tagged option.
     *
     * \param params The data to be used for this FH pattern table option.
     */
    void fh_pattern_table(const fh_pattern_type& params);

    /**
     * \brief Helper method to set the Power Constraint tagged option.
     *
     * \param local_power_constraint The value of the local power constraint field.
     */
    void power_constraint(uint8_t local_power_constraint);

    /**
     * \brief Helper method to set the Channel Switch tagged option.
     *
     * \param data The value of the Channel Switch option.
     */
    void channel_switch(const channel_switch_type& data);

    /**
     * \brief Helper method to set the Quiet tagged option.
     *
     * \param data The value of the quiet count field.
     */
    void quiet(const quiet_type& data);

    /**
     * \brief Helper method to set the TPC Report tagged option.
     *
     * \param transmit_power uint8_t with the value of the transmit power field.
     * \param link_margin uint8_t with the value of the link margin field.
     */
    void tpc_report(uint8_t transmit_power, uint8_t link_margin);

    /**
     * \brief Helper method to set the ERP Information tagged option.
     *
     * \param value The value to set in this erp information option.
     */
    void erp_information(uint8_t value);

    /**
     * \brief Helper method to set the BSS Load tagged option.
     *
     * \param data The value to set in this bss load option.
     */
    void bss_load(const bss_load_type& data);

    /**
     * \brief Helper method to set the TIM tagged option.
     *
     * \brief data The value to set in this tim option.
     */
    void tim(const tim_type& data);

    /**
     * \brief Helper method to set the HT capabilities tagged option.
     *
     * \brief data The value to set in this ht capabilities option.
     */
    void ht_capability(const ht_capability_type& data);

    /**
     * \brief Helper method to set the extended capabilities tagged option.
     *
     * \brief data The value to set in this extended capabilities option.
     */
    void ext_capability(const ext_capability_type& data);
    
    /**
     * \brief Helper method to set the VHT capabilities tagged option.
     *
     * \brief data The value to set in this vht capabilities option.
     */
    void vht_capability(const vht_capability_type& data);
    
    /**
     * \brief Helper method to set the Challenge Text tagged option.
     *
     * \brief text The challenge text to be added.
     */
    void challenge_text(const std::string& text);

    /**
     * \brief Helper method to add a Vendor Specific tagged option.
     *
     * \brief text The option to be added.
     */
    void vendor_specific(const vendor_specific_type& data);
    
    // Option searching helpers
    
    /**
     * \brief Helper method to search for this PDU's rsn information 
     * option.
     * 
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return std::string containing the ssid.
     */
    RSNInformation rsn_information() const;
    
    /**
     * \brief Helper method to search for this PDU's SSID.
     * 
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return std::string containing the SSID.
     */
    std::string ssid() const;

    /**
     * \brief Helper method to get the supported rates.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return rates_type containing the supported rates.
     */
    rates_type supported_rates() const;

    /**
     * \brief Helper method to get the extended supported rates.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return rates_type containing the extended supported rates.
     */
    rates_type extended_supported_rates() const;

    /**
     * \brief Helper method to get the QOS capability.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return uint8_t containing the QOS capability.
     */
    qos_capability_type qos_capability() const;

    /**
     * \brief Helper method to get the power capability.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return std::pair<uint8_t, uint8_t> containing the power capability.
     */
    std::pair<uint8_t, uint8_t> power_capability() const;
    
    /**
     * \brief Helper method to get the supported channels.
     *
     * Each element in the provided vector is a tuple 
     * (First channel number, number of channels), as defined in the
     * standard.
     * 
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return channels_type containing the power capability.
     */
    channels_type supported_channels() const;
    
    /**
     * \brief Helper method to get the request information.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return request_info_type containing the request information.
     */
    request_info_type request_information() const;
    
    /**
     * \brief Helper method to get the fh parameter set.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return fh_params_set containing the fh parameter set.
     */
    fh_params_set fh_parameter_set() const;
    
    /**
     * \brief Helper method to get the DSSS parameter set.
     * 
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return The access point's current channel.
     */
    uint8_t ds_parameter_set() const;

    /**
     * \brief Helper method to get the CF parameter set.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return The CF parameter set.
     */
    cf_params_set cf_parameter_set() const;
    
    
    /**
     * \brief Helper method to get the ibss parameter set.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return uint16_t containing the ibss parameter set.
     */
    uint16_t ibss_parameter_set() const;
    
    /**
     * \brief Helper method to get the ibss dfs.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return ibss_dfs_params containing the ibss dfs.
     */
    ibss_dfs_params ibss_dfs() const;
    
    /**
     * \brief Helper method to get the country option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return country_params containing the country attributes.
     */
    country_params country() const;
    
    /**
     * \brief Helper method to get the fh parameters option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return std::pair<uint8_t, uint8_t> containing the fh parameters.
     */
    std::pair<uint8_t, uint8_t> fh_parameters() const;
    
    /**
     * \brief Helper method to get the fh patterns option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return fh_pattern_type containing the fh patterns.
     */
    fh_pattern_type fh_pattern_table() const;
    
    /**
     * \brief Helper method to get the power constraint option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return uint8_t containing the power constraint.
     */
    uint8_t power_constraint() const;
    
    /**
     * \brief Helper method to get the channel switch option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return channel_switch_type containing the channel switch.
     */
    channel_switch_type channel_switch() const;
    
    /**
     * \brief Helper method to get the quiet option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return quiet_type containing the quiet option value.
     */
    quiet_type quiet() const;
    
    /**
     * \brief Helper method to get the tpc report option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return quiet_type containing the tpc report option value.
     */
    std::pair<uint8_t, uint8_t> tpc_report() const;
    
    /**
     * \brief Helper method to get the erp information option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return quiet_type containing the erp information option value.
     */
    uint8_t erp_information() const;
    
    /**
     * \brief Helper method to get the bss load option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return quiet_type containing the bss load option value.
     */
    bss_load_type bss_load() const;
    
    /**
     * \brief Helper method to get the tim option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return tim_type containing the tim option value.
     */
    tim_type tim() const;

    /**
     * \brief Helper method to get the HT capabilities option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return ht_capability_type containing the HT capabilities option value.
     */
    ht_capability_type ht_capability() const;

    /**
     * \brief Helper method to get the extended capabilities option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return ht_capability_type containing the extended capabilities option value.
     */
    ext_capability_type ext_capability() const;
    
    /**
     * \brief Helper method to get the VHT capabilities option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return ht_capability_type containing the VHT capabilities option value.
     */
    vht_capability_type vht_capability() const;
    
    /**
     * \brief Helper method to get the challenge text option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return std::string containing the challenge text option value.
     */
    std::string challenge_text() const;
    
    /**
     * \brief Helper method to get a Vendor Specific option.
     *
     * An option_not_found exception is thrown if the option has not 
     * been set.
     * 
     * \return vendor_specific_type containing the option value.
     */
    vendor_specific_type vendor_specific() const;

    // ************************

    /**
     * \brief Returns the 802.11 frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     *
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11::matches_flag(flag);
    }
protected:
    TINS_BEGIN_PACK
    struct dot11_extended_header {
        uint8_t addr2[address_type::address_size];
        uint8_t addr3[address_type::address_size];
        uint16_t frag_seq;
    } TINS_END_PACK;

    
    Dot11ManagementFrame(const address_type& dst_hw_addr = address_type(), 
                         const address_type& src_hw_addr = address_type());
    
    /**
     * \brief Constructs a Dot11ManagementFrame object from a buffer 
     * and adds all identifiable PDUs found in the buffer as children 
     * of this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for the header in the buffer
     * or the input data is malformed, a malformed_packet exception 
     * is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11ManagementFrame(const uint8_t* buffer, uint32_t total_sz);

    void write_ext_header(Memory::OutputMemoryStream& stream);

    uint32_t management_frame_size() { 
        return Dot11ManagementFrame::header_size();
    }
private:
    static std::vector<uint8_t> serialize_rates(const rates_type& rates);
    static rates_type deserialize_rates(const option* option);
    
    template<typename T>
    T search_and_convert(OptionTypes opt_type) const {
        const option* opt = search_option(opt_type);
        if (!opt) {
            throw option_not_found();
        }
        return opt->to<T>();
    }

    dot11_extended_header ext_header_;
    address_type addr4_;
};

} // namespace Tins

#endif // TINS_DOT11_DOT11_MGMT_H
