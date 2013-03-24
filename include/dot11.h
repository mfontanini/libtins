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

#ifndef TINS_DOT_11
#define TINS_DOT_11

#include <list>
#include <vector>
#include <stdint.h>
#include <utility>

#include "macros.h"
#include "pdu.h"
#include "endianness.h"
#include "hw_address.h"
#include "small_uint.h"
#include "pdu_option.h"
#include "network_interface.h"
#include "cxxstd.h"

namespace Tins {
    class RSNInformation;

    /**
     * \brief Class representing an 802.11 frame.
     */
    class Dot11 : public PDU {
    public:
        typedef HWAddress<6> address_type;
    
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11;
    
        /**
         * \brief Broadcast hardware address.
         */
        static const address_type BROADCAST;

        /**
         * \brief Enum for the different types of 802.11 frames.
         *
         */
        enum Types {
            MANAGEMENT = 0,
            CONTROL = 1,
            DATA = 2
        };

        /**
         * \brief Enum for the different types of tagged options.
         */
        enum TaggedOption {
            SSID,
            SUPPORTED_RATES,
            FH_SET,
            DS_SET,
            CF_SET,
            TIM,
            IBSS_SET,
            COUNTRY,
            HOPPING_PATTERN_PARAMS,
            HOPPING_PATTERN_TABLE,
            REQUEST_INFORMATION,
            BSS_LOAD,
            EDCA,
            TSPEC,
            TCLAS,
            SCHEDULE,
            CHALLENGE_TEXT,
            POWER_CONSTRAINT = 32,
            POWER_CAPABILITY,
            TPC_REQUEST,
            TPC_REPORT,
            SUPPORTED_CHANNELS,
            CHANNEL_SWITCH,
            MEASUREMENT_REQUEST,
            MEASUREMENT_REPORT,
            QUIET,
            IBSS_DFS,
            ERP_INFORMATION,
            TS_DELAY,
            TCLAS_PROCESSING,
            QOS_CAPABILITY = 46,
            RSN = 48,
            EXT_SUPPORTED_RATES = 50
        };

        /**
         * \brief Enum for the different subtypes of 802.11 management frames.
         *
         */
        enum ManagementSubtypes {
            ASSOC_REQ = 0,
            ASSOC_RESP = 1,
            REASSOC_REQ = 2,
            REASSOC_RESP = 3,
            PROBE_REQ = 4,
            PROBE_RESP = 5,
            BEACON = 8,
            ATIM = 9,
            DISASSOC = 10,
            AUTH = 11,
            DEAUTH = 12
        };

        /**
         * \brief Enum for the different subtypes of 802.11 control frames.
         *
         */
        enum ControlSubtypes {
            BLOCK_ACK_REQ = 8,
            BLOCK_ACK = 9,
            PS = 10,
            RTS = 11,
            CTS = 12,
            ACK = 13,
            CF_END = 14,
            CF_END_ACK = 15
        };

        /**
         * \brief Enum fro the different subtypes of 802.11 data frames.
         *
         */
        enum DataSubtypes {
            DATA_DATA = 0,
            DATA_CF_ACK = 1,
            DATA_CF_POLL = 2,
            DATA_CF_ACK_POLL = 3,
            DATA_NULL = 4,
            CF_ACK = 5,
            CF_POLL = 6,
            CF_ACK_POLL = 7,
            QOS_DATA_DATA = 8,
            QOS_DATA_CF_ACK = 9,
            QOS_DATA_CF_POLL = 10,
            QOS_DATA_CF_ACK_POLL = 11,
            QOS_DATA_NULL = 12
        };

        /**
         * \brief IEEE 802.11 options struct.
         */
        typedef PDUOption<uint8_t> dot11_option;
        
        /**
         * \brief Constructor for creating an 802.11 PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11(const address_type &dst_hw_addr = address_type(), 
               PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the protocol version.
         *
         * \return uint8_t containing the protocol version.
         */
        small_uint<2> protocol() const { return _header.control.protocol; }

        /**
         * \brief Getter for the 802.11 frame's type.
         *
         * \return uint8_t containing the type of this 802.11 frame.
         */
        small_uint<2> type() const { return _header.control.type; }

        /**
         * \brief Getter for the 802.11 frame's subtype.
         *
         * \return uint8_t cotaining the subtype of this 802.11 frame.
         */
        small_uint<4> subtype() const { return _header.control.subtype; }

        /**
         * \brief Getter for the 802.11 frame's To-DS field.
         *
         * \return small_uint<1> containing the To-DS field.
         */
        small_uint<1> to_ds() const { return _header.control.to_ds; }

        /**
         * \brief Getter for the 802.11 frame's From-DS field.
         *
         * \return small_uint<1> containing the From-DS field.
         */
        small_uint<1> from_ds() const { return _header.control.from_ds; }

        /**
         * \brief Getter for the 802.11 frame's More-Frag field.
         *
         * \return small_uint<1> containing the More-Frag field.
         */
        small_uint<1> more_frag() const { return _header.control.more_frag; }

        /**
         * \brief Getter for the 802.11 frame's Retry field.
         *
         * \return small_uint<1> containing the Retry field.
         */
        small_uint<1> retry() const { return _header.control.retry; }

        /**
         * \brief Getter for the 802.11 frame's Power-Management field.
         *
         * \return small_uint<1> containing the Power-Management field.
         */
        small_uint<1> power_mgmt() const { return _header.control.power_mgmt; }

        /**
         * \brief Getter for the 802.11 frame's WEP field.
         *
         * \return small_uint<1> containing the WEP field.
         */
        small_uint<1> wep() const { return _header.control.wep; }

        /**
         * \brief Getter for the 802.11 frame's Order field.
         *
         * \return small_uint<1> containing the Order field.
         */
        small_uint<1> order() const { return _header.control.order; }

        /**
         * \brief Getter for the Duration-ID field.
         *
         * \return uint16_t containing the Duration-ID field.
         */
        uint16_t duration_id() const { return Endian::le_to_host(_header.duration_id); }

        /**
         * \brief Getter for the first address.
         *
         * \return address_type containing the first address.
         */
        address_type addr1() const { return _header.addr1; }

        /**
         * \brief Getter for the network interface.
         *
         * \return const NetworkInterface& containing the network 
         * interface in which this PDU will be sent.
         */
        const NetworkInterface &iface() const { return _iface; }

        /**
         * \brief Setter for the protocol version.
         *
         * \param new_proto The new protocol version.
         */
        void protocol(small_uint<2> new_proto);

        /**
         * \brief Setter for the 802.11 frame's type.
         *
         * \param new_type The new type of this 802.11 frame.
         */
        void type(small_uint<2> new_type);

        /**
         * \brief Setter for the 802.11 frame's subtype.
         *
         * \param new_subtype The new subtype of this 802.11 frame.
         */
        void subtype(small_uint<4> new_subtype);

        /**
         * \brief Setter for the 802.11 frame's To-DS field.
         *
         * \param new_value The new value of the To-DS field.
         */
        void to_ds(small_uint<1> new_value);

        /**
         * \brief Setter for the 802.11 frame's From-DS field.
         *
         * \param new_value The new value of the From-DS field.
         */
        void from_ds(small_uint<1> new_value);

        /**
         * \brief Setter for the 802.11 frame's More-Frag field.
         *
         * \param new_value The new value of the More-Frag field.
         */
        void more_frag(small_uint<1> new_value);

        /**
         * \brief Setter for the 802.11 frame's Retry field.
         *
         * \param new_value sThe new value of the Retry field.
         */
        void retry(small_uint<1> new_value);

        /**
         * \brief Setter for the 802.11 frame's Power-Management field.
         *
         * \param new_value The new value of the Power-Management field.
         */
        void power_mgmt(small_uint<1> new_value);

        /**
         * \brief Setter for the 802.11 frame's WEP field.
         *
         * \param new_value The new value of the WEP field.
         */
        void wep(small_uint<1> new_value);

        /**
         * \brief Setter for the 802.11 frame's Order field.
         *
         * \param new_value The new value of the Order field.
         */
        void order(small_uint<1> new_value);

        /**
         * \brief Setter for the Duration-ID field.
         *
         * \param new_duration_id The new value of the Duration-ID field.
         */
        void duration_id(uint16_t new_duration_id);

        /**
         * \brief Setter for the first address.
         *
         * \param new_addr1 The new first address.
         */
        void addr1(const address_type &new_addr1);

        /**
         * \brief Setter for the network interface.
         *
         * \param new_iface The network interface in which this PDU
         * will be sent.
         */
        void iface(const NetworkInterface &new_iface);

        /* Virtual methods */
        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
        
        #ifndef WIN32
        /**
         * \sa PDU::send()
         */
        void send(PacketSender &sender);
        #endif // WIN32

        /**
         * \brief Adds a new option to this Dot11 PDU.
         * \param opt The option to be added.
         */
        void add_tagged_option(const dot11_option &opt);
        
        #if TINS_IS_CXX11
            /**
             * \brief Adds a new option to this Dot11 PDU.
             * 
             * The option is move-constructed
             * 
             * \param opt The option to be added.
             */
            void add_tagged_option(dot11_option &&opt);
        #endif

        /**
         * \brief Looks up a tagged option in the option list.
         * 
         * The returned pointer <b>must not</b> be free'd.
         * 
         * \param opt The option identifier.
         * \return The option found, or 0 if no such option has been set.
         */
        const dot11_option *search_option(TaggedOption opt) const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }
        
        /**
         * \sa PDU::clone
         */
        Dot11 *clone() const {
            return new Dot11(*this);
        }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag;
        }

        /**
         * \brief Allocates an Dot11 PDU from a buffer.
         * 
         * This can be used somehow as a "virtual constructor". This 
         * method instantiates a subclass of Dot11 from the given buffer.
         * The allocated class' type will be figured out from the
         * information provided in the buffer.
         * 
         * \param buffer The buffer from which to take the PDU data.
         * \param total_sz The total size of the buffer.
         * \return The allocated Dot11 PDU.
         */
        static Dot11 *from_bytes(const uint8_t *buffer, uint32_t total_sz);
    protected:
        virtual uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz) { return 0; }
        virtual uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) { return 0; }
        void parse_tagged_parameters(const uint8_t *buffer, uint32_t total_sz);
        void add_tagged_option(TaggedOption opt, uint8_t len, const uint8_t *val);
    protected:
        /**
         * Struct that represents the 802.11 header
         */
        TINS_BEGIN_PACK
        struct ieee80211_header {
            TINS_BEGIN_PACK
            struct {
            #if TINS_IS_LITTLE_ENDIAN
                uint16_t protocol:2,
                        type:2,
                        subtype:4,
                        to_ds:1,
                        from_ds:1,
                        more_frag:1,
                        retry:1,
                        power_mgmt:1,
                        more_data:1,
                        wep:1,
                        order:1;
            #elif TINS_IS_BIG_ENDIAN
                uint16_t subtype:4,
                        type:2,
                        protocol:2,
                        order:1,
                        wep:1,
                        more_data:1,
                        power_mgmt:1,
                        retry:1,
                        more_frag:1,
                        from_ds:1,
                        to_ds:1;
            #endif
            } TINS_END_PACK control;
            uint16_t duration_id;
            uint8_t addr1[address_type::address_size];

        } TINS_END_PACK;
    private:
        Dot11(const ieee80211_header *header_ptr);
        
        void internal_add_option(const dot11_option &opt);
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);


        ieee80211_header _header;
        NetworkInterface _iface;
        uint32_t _options_size;
        std::list<dot11_option> _options;
    };

    /**
     * \brief Abstract class that englobes all Management frames in the 802.11 protocol.
     */
    class Dot11ManagementFrame : public Dot11 {
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
         * The requested information container type.
         */
        typedef std::vector<uint8_t> request_info_type;
    
        /**
         * This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_MANAGEMENT;

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
         * Represents the IEEE 802.11 frames' capability information.
         */
        TINS_BEGIN_PACK
        class capability_information {
        private:
            #if TINS_IS_LITTLE_ENDIAN
                uint16_t _ess:1,
                         _ibss:1,
                         _cf_poll:1,
                         _cf_poll_req:1,
                         _privacy:1,
                         _short_preamble:1,
                         _pbcc:1,
                         _channel_agility:1,
                         _spectrum_mgmt:1,
                         _qos:1,
                         _sst:1,
                         _apsd:1,
                         _reserved:1,
                         _dsss_ofdm:1,
                         _delayed_block_ack:1,
                         _immediate_block_ack:1;
            #elif TINS_IS_BIG_ENDIAN
                uint16_t _channel_agility:1,
                         _pbcc:1,
                         _short_preamble:1,
                         _privacy:1,
                         _cf_poll_req:1,
                         _cf_poll:1,
                         _ibss:1,
                        _ess:1,
                        _immediate_block_ack:1,
                         _delayed_block_ack:1,
                         _dsss_ofdm:1,
                         _reserved:1,
                         _apsd:1,
                         _sst:1,
                         _qos:1,
                         _spectrum_mgmt:1;
            #endif
        public:
            /**
             * \brief Getter for the ess flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool ess() const { return _ess; }

            /**
             * \brief Getter for the ibss flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool ibss() const { return _ibss; }

            /**
             * \brief Getter for the cf_poll flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool cf_poll() const { return _cf_poll; }

            /**
             * \brief Getter for the cf_poll_req flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool cf_poll_req() const { return _cf_poll_req; }

            /**
             * \brief Getter for the privacy flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool privacy() const { return _privacy; }

            /**
             * \brief Getter for the short_preamble flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool short_preamble() const { return _short_preamble; }

            /**
             * \brief Getter for the pbcc flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool pbcc() const { return _pbcc; }

            /**
             * \brief Getter for the channel_agility flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool channel_agility() const { return _channel_agility; }

            /**
             * \brief Getter for the spectrum_mgmt flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool spectrum_mgmt() const { return _spectrum_mgmt; }

            /**
             * \brief Getter for the qos flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool qos() const { return _qos; }

            /**
             * \brief Getter for the sst flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool sst() const { return _sst; }

            /**
             * \brief Getter for the apsd flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool apsd() const { return _apsd; }

            /**
             * \brief Getter for the reserved flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool reserved() const { return _reserved; }

            /**
             * \brief Getter for the dsss_ofdm flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool dsss_ofdm() const { return _dsss_ofdm; }

            /**
             * \brief Getter for the delayed_block_ack flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool delayed_block_ack() const { return _delayed_block_ack; }

            /**
             * \brief Getter for the immediate_block_ack flag.
             *
             * \return Bool indicating the flag's value.
             */
            bool immediate_block_ack() const { return _immediate_block_ack; }

            /**
             * \brief Setter for the ess flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void ess(bool new_value) { _ess = new_value; }

            /**
             * \brief Setter for the ibss flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void ibss(bool new_value) { _ibss = new_value; }

            /**
             * \brief Setter for the cf_poll flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void cf_poll(bool new_value) { _cf_poll = new_value; }

            /**
             * \brief Setter for the cf_poll_req flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void cf_poll_req(bool new_value) { _cf_poll_req = new_value; }

            /**
             * \brief Setter for the privacy flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void privacy(bool new_value) { _privacy = new_value; }

            /**
             * \brief Setter for the short_preamble flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void short_preamble(bool new_value) { _short_preamble = new_value; }

            /**
             * \brief Setter for the pbcc flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void pbcc(bool new_value) { _pbcc = new_value; }

            /**
             * \brief Setter for the channel_agility flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void channel_agility(bool new_value) { _channel_agility = new_value; }

            /**
             * \brief Setter for the spectrum_mgmt flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void spectrum_mgmt(bool new_value) { _spectrum_mgmt = new_value; }

            /**
             * \brief Setter for the qos flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void qos(bool new_value) { _qos = new_value; }

            /**
             * \brief Setter for the sst flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void sst(bool new_value) { _sst = new_value; }

            /**
             * \brief Setter for the apsd flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void apsd(bool new_value) { _apsd = new_value; }

            /**
             * \brief Setter for the reserved flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void reserved(bool new_value) { _reserved = new_value; }

            /**
             * \brief Setter for the dsss_ofdm flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void dsss_ofdm(bool new_value) { _dsss_ofdm = new_value; }

            /**
             * \brief Setter for the delayed_block_ack flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void delayed_block_ack(bool new_value) { _delayed_block_ack = new_value; }

            /**
             * \brief Setter for the immediate_block_ack flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void immediate_block_ack(bool new_value) { _immediate_block_ack = new_value; }

        } TINS_END_PACK;
        
        TINS_BEGIN_PACK
        struct fh_params_set {
            uint16_t dwell_time;
            uint8_t hop_set, hop_pattern, hop_index;
            
            fh_params_set() {}
            
            fh_params_set(uint16_t dwell_time, uint8_t hop_set, 
              uint8_t hop_pattern, uint8_t hop_index) 
            : dwell_time(dwell_time), hop_set(hop_set), 
              hop_pattern(hop_pattern), hop_index(hop_index) {}
        } TINS_END_PACK;
        
        TINS_BEGIN_PACK
        struct cf_params_set {
            uint8_t cfp_count, cfp_period;
            uint16_t cfp_max_duration, cfp_dur_remaining;
            
            cf_params_set() {}
            
            cf_params_set(uint8_t cfp_count, uint8_t cfp_period,
              uint16_t cfp_max_duration, uint16_t cfp_dur_remaining) 
            : cfp_count(cfp_count), cfp_period(cfp_period), 
              cfp_max_duration(cfp_max_duration), 
              cfp_dur_remaining(cfp_dur_remaining) {}
        } TINS_END_PACK;
        
        struct ibss_dfs_params {
            static const size_t minimum_size = address_type::address_size + sizeof(uint8_t) + 2 * sizeof(uint8_t);
            
            address_type dfs_owner;
            uint8_t recovery_interval; 
            channels_type channel_map;
           
            ibss_dfs_params() {}
           
            ibss_dfs_params(const address_type &addr, 
              uint8_t recovery_interval, const channels_type &channels)
            : dfs_owner(addr), recovery_interval(recovery_interval),
              channel_map(channels) {}
        };
        
        struct country_params {
            typedef std::vector<uint8_t> container_type;
            // String identifier: 3 bytes
            static const size_t minimum_size = 3 + sizeof(uint8_t) * 3;
            
            std::string country;
            container_type first_channel, number_channels, max_transmit_power;
            
            country_params() {}
            
            country_params(const std::string &country, const container_type &first,
              const container_type &number, const container_type &max) 
            : country(country), first_channel(first), number_channels(number),
              max_transmit_power(max) {}
        };
        
        struct fh_pattern_type {
            typedef std::vector<uint8_t> container_type;
            static const size_t minimum_size = sizeof(uint8_t) * 4;
            
            uint8_t flag, number_of_sets, modulus, offset;
            container_type random_table;
            
            fh_pattern_type() {}
            
            fh_pattern_type(uint8_t flag, uint8_t sets, uint8_t modulus,
              uint8_t offset, const container_type& table) 
            : flag(flag), number_of_sets(sets), modulus(modulus), 
              offset(offset), random_table(table) {}
        };
        
        struct channel_switch_type {
            uint8_t switch_mode, new_channel, switch_count;
            
            channel_switch_type() {}
            
            channel_switch_type(uint8_t mode, uint8_t channel, uint8_t count)
            : switch_mode(mode), new_channel(channel), switch_count(count) { }
        };
        
        struct quiet_type {
            uint8_t quiet_count, quiet_period;
            uint16_t quiet_duration, quiet_offset;
            
            quiet_type() {}
            
            quiet_type(uint8_t count, uint8_t period, uint16_t duration,
              uint16_t offset)
            : quiet_count(count), quiet_period(period), 
            quiet_duration(duration), quiet_offset(offset) {}
        };
        
        struct bss_load_type {
            uint16_t station_count;
            uint16_t available_capacity;
            uint8_t channel_utilization;
            
            bss_load_type() {}
            
            bss_load_type(uint16_t count, uint8_t utilization, 
              uint16_t capacity) 
            : station_count(count), available_capacity(capacity),
            channel_utilization(utilization) {}
        };
        
        struct tim_type {
            typedef std::vector<uint8_t> container_type;
            
            uint8_t dtim_count, dtim_period, bitmap_control;
            container_type partial_virtual_bitmap;
            
            tim_type() {}
            
            tim_type(uint8_t count, uint8_t period, uint8_t control,
              const container_type &bitmap) 
            : dtim_count(count), dtim_period(period), bitmap_control(control),
            partial_virtual_bitmap(bitmap) {}
        };

        /**
         * \brief Getter for the second address.
         *
         * \return address_type containing the second address.
         */
        address_type addr2() const { return _ext_header.addr2; }

        /**
         * \brief Getter for the third address.
         *
         * \return address_type containing the third address.
         */
        address_type addr3() const { return _ext_header.addr3; }

        /**
         * \brief Getter for the fragment number.
         *
         * \return The stored fragment number.
         */
        small_uint<4> frag_num() const { 
            #if TINS_IS_LITTLE_ENDIAN
            return _ext_header.frag_seq & 0xf; 
            #else
            return (_ext_header.frag_seq >> 8) & 0xf; 
            #endif
        }

        /**
         * \brief Getter for the sequence number field.
         *
         * \return The stored sequence number.
         */
        small_uint<12> seq_num() const { 
            #if TINS_IS_LITTLE_ENDIAN
            return (_ext_header.frag_seq >> 4) & 0xfff; 
            #else
            return (Endian::le_to_host<uint16_t>(_ext_header.frag_seq) >> 4) & 0xfff; 
            #endif
        }

        /**
         * \brief Getter for the fourth address.
         *
         * \return address_type containing the fourth address.
         */
        const address_type &addr4() const { return _addr4; }

        /**
         * \brief Setter for the second address.
         *
         * \param new_addr2 The new second address to be set.
         */
        void addr2(const address_type &new_addr2);

        /**
         * \brief Setter for the third address.
         *
         * \param new_addr3 The new third address to be set.
         */
        void addr3(const address_type &new_addr3);

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
        void addr4(const address_type &new_addr4);

        // Option setter helpers
    
        /**
         * \brief Helper method to set the ssid.
         *
         * \param new_ssid The ssid to be set.
         */
        void ssid(const std::string &new_ssid);

        /**
         * \brief Helper method to set the RSN information option.
         *
         * \param info The RSNInformation structure to be set.
         */
        void rsn_information(const RSNInformation& info);

        /**
         * \brief Helper method to set the supported rates.
         *
         * \param new_rates The new rates to be set.
         */
        void supported_rates(const rates_type &new_rates);

        /**
         * \brief Helper method to set the extended supported rates.
         *
         * \param new_rates The new rates to be set.
         */
        void extended_supported_rates(const rates_type &new_rates);

        /**
         * \brief Helper method to set the QoS capabilities.
         *
         * \param new_qos_capabilities uint8_t with the capabilities.
         */
        void qos_capability(uint8_t new_qos_capability);

        /**
         * \brief Helper method to set the power capabilities.
         *
         * \param min_power uint8_t indicating the minimum transmiting power capability.
         * \param max_power uint8_t indicating the maximum transmiting power capability.
         */
        void power_capability(uint8_t min_power, uint8_t max_power);

        /**
         * \brief Helper method to set the supported channels.
         *
         * \param new_channels A list of channels to be set.
         */
        void supported_channels(const channels_type &new_channels);

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
         * \brief Helper method to set the Request Information element.
         *
         * \param elements A list of elements.
         */
        void request_information(const request_info_type elements);

        /**
         * \brief Helper method to set the FH parameter.
         *
         * \param fh_params the fh parameter set.
         */
        void fh_parameter_set(fh_params_set fh_params);

        /**
         * \brief Helper method to set the DS parameter.
         *
         * \param current_channel uint8_t with the value of the current_channel field.
         */
        void ds_parameter_set(uint8_t current_channel);

        /**
         * \brief Helper method to set the CF parameter.
         *
         * \param params the CF parammeters to be set.
         */
        void cf_parameter_set(cf_params_set params);

        /**
         * \brief Helper method to set the IBSS parameter.
         *
         * \param atim_window uint16_t with the value of the ATIM window field.
         */
        void ibss_parameter_set(uint16_t atim_window);

        /**
         * \brief Helper method to set the IBSS DFS tagged option.
         *
         * \param params The IBSS DFS data to be set.
         */
        void ibss_dfs(const ibss_dfs_params &params);

        /**
         * \brief Helper method to set the country tagged option.
         *
         * \param params The data to be used for this country option.
         */
        void country(const country_params &params);

        /**
         * \brief Helper method to set the FH parameters.
         *
         * \param prime_radix uint8_t with the value of the prime radix field.
         * \param number_channels uint8_t with the value of the number channels field.
         */
        void fh_parameters(uint8_t prime_radix, uint8_t number_channels);

        /**
         * \brief Helper method to set the FH pattern table.
         *
         * \param params The data to be used for this fh_pattern_table option.
         */
        void fh_pattern_table(const fh_pattern_type &params);

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
        void channel_switch(const channel_switch_type &data);

        /**
         * \brief Helper method to set the Quiet tagged option.
         *
         * \param data The value of the quiet count field.
         */
        void quiet(const quiet_type &data);

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
        void bss_load(const bss_load_type &data);

        /**
         * \brief Helper method to set the TIM tagged option.
         *
         * \brief data The value to set in this tim option.
         */
        void tim(const tim_type &data);

        /**
         * \brief Helper method to set the Challenge Text tagged option.
         *
         * \brief text The challenge text to be added.
         */
        void challenge_text(const std::string &text);
        
        // Option searching helpers
        
        /**
         * \brief Helper method to search for this PDU's rsn information 
         * option.
         * 
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return std::string containing the ssid.
         */
        RSNInformation rsn_information();
        
        /**
         * \brief Helper method to search for this PDU's ssid.
         * 
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return std::string containing the ssid.
         */
        std::string ssid() const;

        /**
         * \brief Helper method to get the supported rates.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return rates_type containing the supported rates.
         */
        rates_type supported_rates() const;

        /**
         * \brief Helper method to get the extended supported rates.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return rates_type containing the extended supported rates.
         */
        rates_type extended_supported_rates() const;

        /**
         * \brief Helper method to get the QOS capability.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return uint8_t containing the QOS capability.
         */
        uint8_t qos_capability() const;

        /**
         * \brief Helper method to get the power capability.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return std::pair<uint8_t, uint8_t> containing the power capability.
         */
        std::pair<uint8_t, uint8_t> power_capability() const;
        
        /**
         * \brief Helper method to get the supported channels.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return channels_type containing the power capability.
         */
        channels_type supported_channels() const;
        
        /**
         * \brief Helper method to get the request information.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return request_info_type containing the request information.
         */
        request_info_type request_information() const;
        
        /**
         * \brief Helper method to get the fh parameter set.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return fh_params_set containing the fh parameter set.
         */
        fh_params_set fh_parameter_set() const;
        
        /**
         * \brief Helper method to get the ds parameter set.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return uint8_t containing the ds parameter set.
         */
        uint8_t ds_parameter_set() const;
        
        /**
         * \brief Helper method to get the ibss parameter set.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return uint16_t containing the ibss parameter set.
         */
        uint16_t ibss_parameter_set() const;
        
        /**
         * \brief Helper method to get the ibss dfs.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return ibss_dfs_params containing the ibss dfs.
         */
        ibss_dfs_params ibss_dfs() const;
        
        /**
         * \brief Helper method to get the country option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return country_params containing the country attributes.
         */
        country_params country() const;
        
        /**
         * \brief Helper method to get the fh parameters option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return std::pair<uint8_t, uint8_t> containing the fh parameters.
         */
        std::pair<uint8_t, uint8_t> fh_parameters() const;
        
        /**
         * \brief Helper method to get the fh patterns option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return fh_pattern_type containing the fh patterns.
         */
        fh_pattern_type fh_pattern_table() const;
        
        /**
         * \brief Helper method to get the power constraint option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return uint8_t containing the power constraint.
         */
        uint8_t power_constraint() const;
        
        /**
         * \brief Helper method to get the channel switch option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return channel_switch_type containing the channel switch.
         */
        channel_switch_type channel_switch() const;
        
        /**
         * \brief Helper method to get the quiet option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return quiet_type containing the quiet option value.
         */
        quiet_type quiet() const;
        
        /**
         * \brief Helper method to get the tpc report option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return quiet_type containing the tpc report option value.
         */
        std::pair<uint8_t, uint8_t> tpc_report() const;
        
        /**
         * \brief Helper method to get the erp information option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return quiet_type containing the erp information option value.
         */
        uint8_t erp_information() const;
        
        /**
         * \brief Helper method to get the bss load option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return quiet_type containing the bss load option value.
         */
        bss_load_type bss_load() const;
        
        /**
         * \brief Helper method to get the tim option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return tim_type containing the tim option value.
         */
        tim_type tim() const;
        
        /**
         * \brief Helper method to get the challenge text option.
         *
         * Throws a std::runtime_error if the option has not been set.
         * 
         * \return std::string containing the challenge text option value.
         */
        std::string challenge_text() const;
        
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
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11::matches_flag(flag);
        }
    protected:
        TINS_BEGIN_PACK
        struct ExtendedHeader {
            uint8_t addr2[address_type::address_size];
            uint8_t addr3[address_type::address_size];
            uint16_t frag_seq;
        } TINS_END_PACK;

        
        Dot11ManagementFrame(const address_type &dst_hw_addr = address_type(), 
                            const address_type &src_hw_addr = address_type());
        
        /**
         * \brief Constructor which creates a Dot11ManagementFrame object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * 
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ManagementFrame(const uint8_t *buffer, uint32_t total_sz);

        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);

        uint32_t management_frame_size() { 
            return sizeof(ieee80211_header) + sizeof(_ext_header) + 
                    ((from_ds() && to_ds()) ? address_type::address_size : 0); 
        }
    private:
        static uint8_t *serialize_rates(const rates_type &rates);
        static rates_type deserialize_rates(const dot11_option *option);
    
        ExtendedHeader _ext_header;
        address_type _addr4;
    };

    /**
     * \brief Class representing an 802.11 Beacon.
     *
     */
    class Dot11Beacon : public Dot11ManagementFrame {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_BEACON;

        /**
         * \brief Constructor for creating a 802.11 Beacon.
         *
         * Constructs a 802.11 Beacon taking destination and source 
         * hardware address.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11Beacon(const address_type &dst_hw_addr = address_type(), 
                    const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11Beacon object from a buffer and adds
         * all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11Beacon(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the timestamp field.
         *
         * \return The stored timestamp value.
         */
        uint64_t timestamp() const { return Endian::le_to_host(_body.timestamp); }

        /**
         * \brief Getter for the interval field.
         *
         * \return The stored interval value.
         */
        uint16_t interval() const { return Endian::le_to_host(_body.interval); }

        /**
         * \brief Getter for the Capabilities Information structure.
         *
         * \return A constant refereence to the stored Capabilities 
         * Information field.
         */
        const capability_information& capabilities() const { return _body.capability; }

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return A refereence to the stored Capabilities Information 
         * field.
         */
        capability_information& capabilities() { return _body.capability; }

        /**
         * \brief Setter for the timestamp field.
         *
         * \param new_timestamp The timestamp to be set.
         */
        void timestamp(uint64_t new_timestamp);

        /**
         * \brief Setter for the interval field.
         *
         * \param new_interval The interval to be set.
         */
        void interval(uint16_t new_interval);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11Beacon *clone() const {
            return new Dot11Beacon(*this);
        }

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }
    private:
        TINS_BEGIN_PACK
        struct BeaconBody {
            uint64_t timestamp;
            uint16_t interval;
            capability_information capability;
        } TINS_END_PACK;

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

        BeaconBody _body;
    };

    /**
     * \brief Class representing a Disassociation frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11Disassoc : public Dot11ManagementFrame {
    public:
       /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_DIASSOC;
    
        /**
         * \brief Constructor for creating a 802.11 Disassociation.
         *
         * Constructs a 802.11 Disassociation taking the destination
         * and source hardware address.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11Disassoc(const address_type &dst_hw_addr = address_type(), 
                    const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11Disassoc object from a buffer and adds
         * all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11Disassoc(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the reason code field.
         *
         * \return The stored reason code.
         */
        uint16_t reason_code() const { return Endian::le_to_host(_body.reason_code); }

        /**
         * \brief Setter for the reason code field.
         *
         * \param new_reason_code The reason code to be set.
         */
        void reason_code(uint16_t new_reason_code);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11Disassoc *clone() const {
            return new Dot11Disassoc(*this);
        }
    private:
        struct DisassocBody {
            uint16_t reason_code;
        };

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

        DisassocBody _body;
    };

    /**
     * \brief Class representing an Association Request frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11AssocRequest : public Dot11ManagementFrame {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_ASSOC_REQ;

        /**
         * \brief Constructor for creating a 802.11 Association Request.
         *
         * Constructs a 802.11 Association Request taking the
         * destination and source hardware address.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11AssocRequest(const address_type &dst_hw_addr = address_type(), 
                        const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11AssocRequest object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11AssocRequest(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return A constant refereence to the stored Capabilities 
         * Information field.
         */
        const capability_information& capabilities() const { return _body.capability;}

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return A refereence to the stored Capabilities Information 
         * field.
         */
        capability_information& capabilities() { return _body.capability;}

        /**
         * \brief Getter for the listen interval field.
         *
         * \return The stored listen interval field.
         */
        uint16_t listen_interval() const { return Endian::le_to_host(_body.listen_interval); }

        /**
         * \brief Setter for the listen interval field.
         *
         * \param new_listen_interval The listen interval to be set.
         */
        void listen_interval(uint16_t new_listen_interval);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11AssocRequest *clone() const {
            return new Dot11AssocRequest(*this);
        }
    private:
        struct AssocReqBody {
            capability_information capability;
            uint16_t listen_interval;
        };

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

        AssocReqBody _body;
    };

    /**
     * \brief Class representing an Association Response frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11AssocResponse : public Dot11ManagementFrame {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_ASSOC_RESP;

        /**
         * \brief Constructor for creating a 802.11 Association Response.
         *
         * Constructors a 802.11 Association Response taking destination 
         * and source hardware address.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11AssocResponse(const address_type &dst_hw_addr = address_type(), 
                            const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11AssocResponse object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11AssocResponse(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the Capabilities Information field.
         *
         * \return A constant reference to the stored Capabilities 
         * Information field.
         */
        const capability_information& capabilities() const { return _body.capability;}

        /**
         * \brief Getter for the Capabilities Information field.
         *
         * \return A reference to the stored Capabilities 
         * Information field.
         */
        capability_information& capabilities() { return _body.capability;}

        /**
         * \brief Getter for the status code field.
         *
         * \return The stored status code.
         */
        uint16_t status_code() const { return Endian::le_to_host(_body.status_code); }

        /**
         * \brief Getter for the AID field.
         *
         * \return The stored AID field.
         */
        uint16_t aid() const { return Endian::le_to_host(_body.aid); }

        /**
         * \brief Setter for the status code.
         *
         * \param new_status_code The status code to be set.
         */
        void status_code(uint16_t new_status_code);

        /**
         * \brief Setter for the AID field.
         *
         * \param new_aid The AID value to be set.
         */
        void aid(uint16_t new_aid);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11AssocResponse *clone() const {
            return new Dot11AssocResponse(*this);
        }
    private:
        struct AssocRespBody {
            capability_information capability;
            uint16_t status_code;
            uint16_t aid;
        };

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

        AssocRespBody _body;
    };

    /**
     * \brief Class representing an ReAssociation Request frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11ReAssocRequest : public Dot11ManagementFrame {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_REASSOC_REQ;

        /**
         * \brief Constructor for creating a 802.11 ReAssociation Request.
         *
         * Constructors a 802.11 Association Request taking the destination 
         * and source hardware address.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11ReAssocRequest(const address_type &dst_hw_addr = address_type(), 
                            const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11AssocRequest object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ReAssocRequest(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return A constant reference to the stored Capabilities 
         * Information field.
         */
        const capability_information& capabilities() const { return _body.capability;}

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return A reference to the stored Capabilities Information 
         * field.
         */
        capability_information& capabilities() { return _body.capability;}

        /**
         * \brief Getter for the listen interval field.
         *
         * \return The stored listen interval.
         */
        uint16_t listen_interval() const { return Endian::le_to_host(_body.listen_interval); }

        /**
         * \brief Getter for the current ap field.
         *
         * \return The current ap.
         */
        address_type current_ap() const { return _body.current_ap; }

        /**
         * \brief Setter for the listen interval field.
         *
         * \param new_listen_interval The listen interval to be set.
         */
        void listen_interval(uint16_t new_listen_interval);

        /**
         * \brief Setter for the current ap.
         *
         * \param new_current_ap The address of the current ap.
         */
        void current_ap(const address_type &new_current_ap);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11ReAssocRequest *clone() const {
            return new Dot11ReAssocRequest(*this);
        }
    private:
        struct ReAssocReqBody {
            capability_information capability;
            uint16_t listen_interval;
            uint8_t current_ap[address_type::address_size];
        };

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

        ReAssocReqBody _body;
    };

    /**
     * \brief Class representing an ReAssociation Response frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11ReAssocResponse : public Dot11ManagementFrame {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_REASSOC_RESP;

        /**
         * \brief Constructor for creating a 802.11 Association Response.
         *
         * Constructs a 802.11 ReAssociation Response taking the 
         * destination and source hardware address.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11ReAssocResponse(const address_type &dst_hw_addr = address_type(), 
                            const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11ReAssocResponse object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ReAssocResponse(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return A constant reference to the stored Capabilities 
         * Information field.
         */
        const capability_information& capabilities() const { return _body.capability;}

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return A reference to the stored Capabilities Information 
         * field.
         */
        capability_information& capabilities() { return _body.capability;}

        /**
         * \brief Getter for the status code field.
         *
         * \return The stored status code.
         */
        uint16_t status_code() const { return Endian::le_to_host(_body.status_code); }

        /**
         * \brief Getter for the AID field.
         *
         * \return The stored AID field value.
         */
        uint16_t aid() const { return Endian::le_to_host(_body.aid); }

        /**
         * \brief Setter for the status code field.
         *
         * \param new_status_code The status code to be set.
         */
        void status_code(uint16_t new_status_code);

        /**
         * \brief Setter for the AID field.
         *
         * \param new_aid The AID to be set.
         */
        void aid(uint16_t new_aid);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11ReAssocResponse *clone() const {
            return new Dot11ReAssocResponse(*this);
        }
    private:
        struct ReAssocRespBody {
            capability_information capability;
            uint16_t status_code;
            uint16_t aid;
        };

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

        ReAssocRespBody _body;
    };

    /**
     * \brief Class representing an Authentication Request frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11Authentication : public Dot11ManagementFrame {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_AUTH;

        /**
         * \brief Constructor for creating a 802.11 Authentication.
         *
         * Constructs a 802.11 Dot11Authentication taking the 
         * destination and source hardware address.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11Authentication(const address_type &dst_hw_addr = address_type(), 
                            const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11Authentication object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11Authentication(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the Authetication Algorithm Number field.
         *
         * \return The stored authentication algorithm number.
         */
        uint16_t auth_algorithm() const {return Endian::le_to_host(_body.auth_algorithm); }

        /**
         * \brief Getter for the Authetication Sequence Number field.
         *
         * \return The stored authentication sequence number.
         */
        uint16_t auth_seq_number() const {return Endian::le_to_host(_body.auth_seq_number); }

        /**
         * \brief Getter for the status code field.
         *
         * \return The stored status code.
         */
        uint16_t status_code() const { return Endian::le_to_host(_body.status_code); }

        /**
         * \brief Setter for the Authetication Algorithm Number field.
         *
         * \param new_auth_algorithm The Authetication Algorithm Number 
         * to be set.
         */
        void auth_algorithm(uint16_t new_auth_algorithm);

        /**
         * \brief Setter for the Authetication Sequence Number field.
         *
         * \param new_auth_seq_number The Authetication Sequence Number 
         * to be set.
         */
        void auth_seq_number(uint16_t new_auth_seq_number);

        /**
         * \brief Setter for the status code field.
         *
         * \param new_status_code The status code to be set.
         */
        void status_code(uint16_t new_status_code);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11Authentication *clone() const {
            return new Dot11Authentication(*this);
        }
    private:
        struct AuthBody {
            uint16_t auth_algorithm;
            uint16_t auth_seq_number;
            uint16_t status_code;
        };

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

        AuthBody _body;

    };

    /**
     * \brief Class representing a Deauthentication frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11Deauthentication : public Dot11ManagementFrame {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_DEAUTH;

        /**
         * \brief Constructor for creating a 802.11 Deauthentication.
         *
         * Constructs a 802.11 Deauthentication taking the 
         * destination and source hardware address.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11Deauthentication(const address_type &dst_hw_addr = address_type(), 
                            const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11Deauthentication object from a buffer and adds
         * all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11Deauthentication(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the reason code field.
         *
         * \return The reason code to be set.
         */
        uint16_t reason_code() const { return Endian::le_to_host(_body.reason_code); }

        /**
         * \brief Setter for the reason code field.
         *
         * \param new_reason_code The reason code to be set.
         */
        void reason_code(uint16_t new_reason_code);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11Deauthentication *clone() const {
            return new Dot11Deauthentication(*this);
        }
    private:
        struct DeauthBody {
            uint16_t reason_code;
        };

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

        DeauthBody _body;
    };

    /**
     * \brief Class representing an Probe Request frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11ProbeRequest : public Dot11ManagementFrame {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_PROBE_REQ;

        /**
         * \brief Constructor for creating a 802.11 Probe Request.
         *
         * Constructs a 802.11 Probe Request taking the 
         * destination and source hardware address.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11ProbeRequest(const address_type &dst_hw_addr = address_type(), 
                        const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11ProbeRequest object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ProbeRequest(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::DOT11_PROBE_REQ; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone()
         */
        Dot11ProbeRequest* clone() const {
            return new Dot11ProbeRequest(*this);
        }

    };

    /**
     * \brief Class representing an Probe Response frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11ProbeResponse : public Dot11ManagementFrame {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_PROBE_RESP;

        /**
         * \brief Constructor for creating a 802.11 Probe Response.
         *
         * Constructs a 802.11 Probe Response taking the
         * destination and source hardware addresses.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         */
        Dot11ProbeResponse(const address_type &dst_hw_addr = address_type(), 
                        const address_type &src_hw_addr = address_type());

        /**
         * \brief Constructor which creates a Dot11ProbeResponse object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ProbeResponse(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the timestamp field.
         *
         * \return The stored timestamp value.
         */
        uint64_t timestamp() const { return Endian::le_to_host(_body.timestamp); }

        /**
         * \brief Getter for the interval field.
         *
         * \return The stored interval value.
         */
        uint16_t interval() const { return Endian::le_to_host(_body.interval); }

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return A constant reference to the stored Capabilities 
         * Information field.
         */
        const capability_information& capabilities() const { return _body.capability;}

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return A reference to the stored Capabilities Information 
         * field.
         */
        capability_information& capabilities() { return _body.capability;}

        /**
         * \brief Setter for the timestamp field.
         *
         * \param new_timestamp The timestamp to be set.
         */
        void timestamp(uint64_t new_timestamp);

        /**
         * \brief Setter for the interval field.
         *
         * \param new_interval The interval to be set.
         */
        void interval(uint16_t new_interval);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone()
         */
        Dot11ProbeResponse* clone() const {
            return new Dot11ProbeResponse(*this);
        }

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
        }
    protected:

    private:
        TINS_BEGIN_PACK
        struct ProbeResp {
            uint64_t timestamp;
            uint16_t interval;
            capability_information capability;
        } TINS_END_PACK;

        ProbeResp _body;

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

    };

    class Dot11Data : public Dot11 {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_DATA;
        
        /**
         * \brief Constructor for creating a 802.11 Data frame.
         *
         * Constructs a 802.11 Data frame taking the
         * destination and source hardware addresses.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         * \param child The inner PDU.
         */
        Dot11Data(const address_type &dst_hw_addr = address_type(), 
                const address_type &src_hw_addr = address_type(), 
                PDU* child = 0);
                    
        /**
         * \brief Constructor which creates a Dot11Data object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11Data(const uint8_t *buffer, uint32_t total_sz);
        
        /**
         * \brief Getter for the second address.
         *
         * \return The stored second address.
         */
        address_type addr2() const { return _ext_header.addr2; }

        /**
         * \brief Getter for the third address.
         *
         * \return The stored third address.
         */
        address_type addr3() const { return _ext_header.addr3; }

        /**
         * \brief Getter for the fragment number field.
         *
         * \return The stored fragment number.
         */
        small_uint<4> frag_num() const { 
            #if TINS_IS_LITTLE_ENDIAN
            return _ext_header.frag_seq & 0xf; 
            #else
            return (_ext_header.frag_seq >> 8) & 0xf; 
            #endif
        }

        /**
         * \brief Getter for the sequence number field.
         *
         * \return The stored sequence number.
         */
        small_uint<12> seq_num() const { 
            #if TINS_IS_LITTLE_ENDIAN
            return (_ext_header.frag_seq >> 4) & 0xfff; 
            #else
            return (Endian::le_to_host<uint16_t>(_ext_header.frag_seq) >> 4) & 0xfff; 
            #endif
        }

        /**
         * \brief Getter for the fourth address.
         *
         * \return The fourth address.
         */
        address_type addr4() const { return _addr4; }

        /**
         * \brief Setter for the second address.
         *
         * \param new_addr2 The second address to be set.
         */
        void addr2(const address_type &new_addr2);

        /**
         * \brief Setter for the third address.
         *
         * \param new_addr3 The third address to be set.
         */
        void addr3(const address_type &new_addr3);

        /**
         * \brief Setter for the fragment number field.
         *
         * \param new_frag_num The fragment number to be set.
         */
        void frag_num(small_uint<4> new_frag_num);

        /**
         * \brief Setter for the sequence number field.
         *
         * \param new_seq_num The sequence number to be set.
         */
        void seq_num(small_uint<12> new_seq_num);

        /**
         * \brief Setter for the fourth address field.
         *
         * \param new_addr4 The fourth address to be set.
         */
        void addr4(const address_type &new_addr4);

        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11Data *clone() const {
            return new Dot11Data(*this);
        }
    protected:
        TINS_BEGIN_PACK
        struct ExtendedHeader {
            uint8_t addr2[address_type::address_size];
            uint8_t addr3[address_type::address_size];
            uint16_t frag_seq;
        } TINS_END_PACK;

        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);

        uint32_t data_frame_size() { 
            return sizeof(_ext_header) + ((from_ds() && to_ds()) ? sizeof(_addr4) : 0); 
        }
    private:
        ExtendedHeader _ext_header;
        address_type _addr4;
    };

    class Dot11QoSData : public Dot11Data {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_QOS_DATA;

        /**
         * \brief Constructor for creating a 802.11 QoS Data PDU
         *
         * Constructs a 802.11 QoS Data PDU taking the
         * destination and source hardware addresses.
         *
         * \param dst_hw_addr The destination hardware address.
         * \param src_hw_addr The source hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11QoSData(const address_type &dst_hw_addr = address_type(), 
                    const address_type &src_hw_addr = address_type(), 
                    PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 QoS Data object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11QoSData(const uint8_t *buffer, uint32_t total_sz);
        
        /**
         * \brief Getter for the QOS Control field.
         *
         * \return The stored QOS Control field value.
         */
        uint16_t qos_control() const { return Endian::le_to_host(_qos_control); }

        /**
         * \brief Setter for the QOS Control field.
         *
         * \param new_qos_control The QOS Control to be set.
         */
        void qos_control(uint16_t new_qos_control);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11QoSData *clone() const {
            return new Dot11QoSData(*this);
        }

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::DOT11_QOS_DATA; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == PDU::DOT11_QOS_DATA || Dot11Data::matches_flag(flag);
        }
    private:
        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);


        uint16_t _qos_control;
    };

    /**
     * \brief Class that represents an 802.11 control frame.
     */
    class Dot11Control : public Dot11 {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_CONTROL;
        
        /**
         * \brief Constructor for creating a 802.11 control frame PDU
         *
         * Constructs a 802.11 Control PDU taking the destination and 
         * source hardware addresses.
         *
         * \param dst_addr The destination hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11Control(const address_type &dst_addr = address_type(), 
                    PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 control frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11Control(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::DOT11_CONTROL; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == PDU::DOT11_CONTROL || Dot11::matches_flag(flag);
        }
    };

    /**
     * \brief Class that represents an abstraction of the 802.11 control frames
     * that contain a target address.
     */
    class Dot11ControlTA : public Dot11Control {
    public:
        /**
         * \brief Getter for the target address field.
         */
        address_type target_addr() const { return _taddr; }

        /**
         * \brief Setter for the target address field.
         * \param addr The new target address.
         */
        void target_addr(const address_type &addr);
    protected:
        /**
         * \brief Constructor for creating a 802.11 control frame TA PDU
         *
         * Constructs a 802.11 PDU taking the destination and source 
         * hardware addresses.
         *
         * \param dst_addr The destination hardware address.
         * \param target_addr The source hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11ControlTA(const address_type &dst_addr = address_type(), 
                    const address_type &target_addr = address_type(), 
                    PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 control frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ControlTA(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
    protected:
        /**
         * \brief Getter for the control ta additional fields size.
         */
        uint32_t controlta_size() const { return _taddr.size() + sizeof(ieee80211_header); }

        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);
    private:

        address_type _taddr;
    };

    class Dot11RTS : public Dot11ControlTA {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_RTS;

        /**
         * \brief Constructor for creating a 802.11 RTS frame PDU
         *
         * Constructs a 802.11 RTS PDU taking the destination and source
         * hardware addresses.
         *
         * \param dst_addr The destination hardware address.
         * \param target_addr The source hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11RTS(const address_type &dst_addr = address_type(), 
                const address_type &target_addr = address_type(), 
                PDU* child = 0);
                    
        /**
         * \brief Constructor which creates an 802.11 RTS frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11RTS(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11RTS *clone() const {
            return new Dot11RTS(*this);
        }

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11Control::matches_flag(flag);
        }
    };

    class Dot11PSPoll : public Dot11ControlTA {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_PS_POLL;

        /**
         * \brief Constructor for creating a 802.11 PS-Poll frame PDU
         *
         * Constructs a 802.11 PDU taking the destination and source 
         * hardware addresses.
         *
         * \param dst_addr The destination hardware address.
         * \param target_addr The source hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11PSPoll(const address_type &dst_addr = address_type(), 
                    const address_type &target_addr = address_type(), 
                    PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 PS-Poll frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11PSPoll(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11PSPoll *clone() const {
            return new Dot11PSPoll(*this);
        }

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11Control::matches_flag(flag);
        }
    };

    class Dot11CFEnd : public Dot11ControlTA {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_CF_END;

        /**
         * \brief Constructor for creating a 802.11 CF-End frame PDU
         *
         * Constructs a 802.11 PDU taking the destination and source 
         * hardware addresses.
         *
         * \param dst_addr The destination hardware address.
         * \param target_addr The source hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11CFEnd(const address_type &dst_addr = address_type(), 
                const address_type &target_addr = address_type(), 
                PDU* child = 0);
                    
        /**
         * \brief Constructor which creates an 802.11 CF-End frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11CFEnd(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11CFEnd *clone() const {
            return new Dot11CFEnd(*this);
        }

         /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11Control::matches_flag(flag);
        }
    };

    class Dot11EndCFAck : public Dot11ControlTA {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_END_CF_ACK;

        /**
         * \brief Constructor for creating a 802.11 End-CF-Ack frame PDU
         *
         * Constructs a 802.11 PDU taking the destination and source 
         * hardware addresses.
         * 
         * \param dst_addr The destination hardware address.
         * \param target_addr The source hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11EndCFAck(const address_type &dst_addr = address_type(), 
                    const address_type &target_addr = address_type(), 
                    PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 End-CF-Ack frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11EndCFAck(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11EndCFAck *clone() const {
            return new Dot11EndCFAck(*this);
        }

         /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11Control::matches_flag(flag);
        }
    };

    class Dot11Ack : public Dot11Control {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_ACK;

        /**
         * \brief Constructor for creating a 802.11 Ack frame PDU
         *
         * Constructs a 802.11 PDU taking the destination and source 
         * hardware addresses.
         *
         * \param dst_addr The destination hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11Ack(const address_type &dst_addr = address_type(), 
                PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 Ack frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11Ack(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11Ack *clone() const {
            return new Dot11Ack(*this);
        }

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11Control::matches_flag(flag);
        }
    };

    /**
     * \brief Class that represents an 802.11 Block Ack Request PDU.
     */
    class Dot11BlockAckRequest : public Dot11ControlTA {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_BLOCK_ACK_REQ;

        /**
         * \brief Constructor for creating a 802.11 Block Ack request frame PDU
         *
         * Constructs a 802.11 PDU taking the destination and source 
         * hardware addresses.
         * 
         * \param dst_addr The destination hardware address.
         * \param target_addr The source hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11BlockAckRequest(const address_type &dst_addr = address_type(), 
                            const address_type &target_addr = address_type(), 
                            PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 Block Ack request frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11BlockAckRequest(const uint8_t *buffer, uint32_t total_sz);

        /* Getter */

        /**
         * \brief Getter for the bar control field.
         * \return The stored bar control field.
         */
        uint16_t bar_control() const { return Endian::le_to_host(_bar_control.tid); }

        /**
         * \brief Getter for the start sequence field.
         * \return The stored start sequence.
         */
        uint16_t start_sequence() const { return Endian::le_to_host(_start_sequence.seq); }
        
        /**
         * \brief Getter for the fragment number field.
         * \return The stored fragment number field.
         */
        uint8_t fragment_number() const { return _start_sequence.frag; }
        
        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return The header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /* Setter */

        /**
         * \brief Setter for the bar control field.
         * \param bar The bar control field to be set.
         */
        void bar_control(uint16_t bar);

        /**
         * \brief Setter for the start sequence field.
         * \param bar The start sequence field to be set.
         */
        void start_sequence(uint16_t seq);
        
        /**
         * \brief Setter for the fragment number field.
         * \param frag The fragment number field to be set.
         */
        void fragment_number(uint8_t frag);

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11BlockAckRequest *clone() const {
            return new Dot11BlockAckRequest(*this);
        }

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11Control::matches_flag(flag);
        }
    protected:
        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);
    private:
        TINS_BEGIN_PACK
        struct BarControl {
            uint16_t tid:4,
                reserved:12;
        } TINS_END_PACK;

        TINS_BEGIN_PACK
        struct StartSequence {
            uint16_t frag:4,
                seq:12;
        } TINS_END_PACK;

        void init_block_ack();

        BarControl _bar_control;
        StartSequence _start_sequence;
    };

    /**
     * \brief Class that represents an 802.11 block ack frame.
     */
    class Dot11BlockAck : public Dot11ControlTA {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DOT11_BLOCK_ACK;
        
        /**
         * The size of the bitmap field.
         */
        static const size_t bitmap_size = 8;

        /**
         * \brief Constructor for creating a 802.11 Block Ack frame PDU
         *
         * Constructs a 802.11 PDU taking the destination and source 
         * hardware addresses.
         * 
         * \param dst_addr The destination hardware address.
         * \param target_addr The source hardware address.
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11BlockAck(const address_type &dst_addr = address_type(), 
                    const address_type &target_addr = address_type(), 
                    PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 Block Ack request frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11BlockAck(const uint8_t *buffer, uint32_t total_sz);

        /* Getters */

        /**
         * \brief Getter for the bar control field.
         * \return The stored bar control field.
         */
        uint16_t bar_control() const { return _bar_control.tid; }

        /**
         * \brief Getter for the start sequence field.
         * \return The stored bar start sequence.
         */
        uint16_t start_sequence() const { return (_start_sequence.frag << 12) | (_start_sequence.seq); }
        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /* Setters */

        /**
         * \brief Setter for the bar control field.
         * \param bar The bar control to be set.
         */
        void bar_control(uint16_t bar);

        /**
         * \brief Setter for the start sequence field.
         * \param bar The start sequence  to be set.
         */
        void start_sequence(uint16_t seq);

        /**
         * \brief Getter for the bitmap field.
         * 
         * The returned pointer <b>must not</b> be free'd.
         * 
         * \return The bitmap field.
         */
        const uint8_t *bitmap() const { return _bitmap; }

        /**
         * \brief Setter for the bitmap field.
         * \param bit The new bitmap field to be set.
         */
        void bitmap(const uint8_t *bit);

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }

        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == pdu_flag || Dot11Control::matches_flag(flag);
        }

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone
         */
        Dot11BlockAck *clone() const {
            return new Dot11BlockAck(*this);
        }
    private:
        TINS_BEGIN_PACK
        struct BarControl {
            uint16_t reserved:12,
                tid:4;
        } TINS_END_PACK;

        TINS_BEGIN_PACK
        struct StartSequence {
            uint16_t frag:4,
                seq:12;
        } TINS_END_PACK;

        void init_block_ack();
        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);


        BarControl _bar_control;
        StartSequence _start_sequence;
        uint8_t _bitmap[bitmap_size];
    };
}

#endif // TINS_DOT_11
