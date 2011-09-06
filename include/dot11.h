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

#ifndef __DOT_11
#define __DOT_11

#include <list>
#include <stdint.h>
#include <stdexcept>
#include <utility>

#include "pdu.h"
#include "utils.h"

namespace Tins {

    /**
     * \brief Class representing an 802.11 frame.
     */
    class Dot11 : public PDU {
    public:
        /**
         * \brief Broadcast hardware address.
         */
        static const uint8_t *BROADCAST;

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
            BSS,
            COUNTRY,
            HOPPING_PATTERN_PARAMS,
            HOPPING_PATTERN_TABLE,
            REQUEST,
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
        struct Dot11_Option {
            /**
             * \brief The option number.
             */
            uint8_t option;
            /**
             * \brief The value's length in bytes.
             */
            uint8_t length;
            /**
             * \brief The option's value.
             */
            uint8_t *value;

            /**
             * \brief Creates an instance of Dot11_Option.
             *
             * The option's value is copied, therefore the user should
             * manually free any memory pointed by the "val" parameter.
             * \param opt The option number.
             * \param len The length of the option's value in bytes.
             * \param val The option's value.
             */
            Dot11_Option(uint8_t opt, uint8_t len, const uint8_t *val);
        };

        /**
         * \brief Constructor for creating a 802.11 PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         *
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11(const uint8_t* dst_hw_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11(const std::string& iface, const uint8_t* dst_hw_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11(uint32_t iface_index, const uint8_t* dst_hw_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Copy constructor.
         */
        Dot11(const Dot11 &other);

        /**
         * \brief Dot11 destructor.
         *
         * Releases the memory allocated for tagged options.
         */
        ~Dot11();

        /**
         * \brief Copy assignment operator.
         */
        Dot11 &operator= (const Dot11 &other);

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
         * \brief Getter for the first address.
         *
         * \return The first address as a constant uint8_t pointer.
         */
        inline const uint8_t* addr1() const { return this->_header.addr1; }

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
         * \brief Setter for the first address.
         *
         * \param new_addr1 const uint8_t array of 6 bytes containing the new first's address.
         */
        void addr1(const uint8_t* new_addr1);

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
         * \brief Adds a new option to this Dot11 PDU.
         *
         * This copies the value buffer.
         * \param opt The option identifier.
         * \param len The length of the value field.
         * \param val The value of this option.
         */
        void add_tagged_option(TaggedOption opt, uint8_t len, const uint8_t *val);

        /**
         * \brief Looks up a tagged option in the option list.
         * \param opt The option identifier.
         * \return The option found, or 0 if no such option has been set.
         */
        const Dot11_Option *lookup_option(TaggedOption opt) const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::DOT11; }

        /**
         * \brief Allocates an Dot11 PDU from a buffer.
         * \param buffer The buffer from which to take the PDU data.
         * \param total_sz The total size of the buffer.
         * \return The allocated PDU.
         */
        static PDU *from_bytes(const uint8_t *buffer, uint32_t total_sz);
    protected:
        virtual uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz) { return 0; }
        virtual uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) { return 0; }
        void parse_tagged_parameters(const uint8_t *buffer, uint32_t total_sz);
        void copy_80211_fields(const Dot11 *other);
    protected:
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
            uint8_t addr1[6];

        } __attribute__((__packed__));
        private:

        Dot11(const ieee80211_header *header_ptr);

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);


        ieee80211_header _header;
        uint32_t _iface_index, _options_size;
        std::list<Dot11_Option> _options;
    };

    /**
     * \brief Class that models the RSN information structure.
     */
    class RSNInformation {
    public:
        /**
         * \brief Enum that represents the different cypher suites.
         */
        enum CypherSuites {
            WEP_40  = 0x01ac0f00,
            TKIP    = 0x02ac0f00,
            CCMP    = 0x04ac0f00,
            WEP_104 = 0x05ac0f00
        };

        /**
         * \brief Enum that represents the different akm suites.
         */
        enum AKMSuites {
            PMKSA = 0x01ac0f00,
            PSK   = 0x02ac0f00
        };

        /**
         * \brief Creates an instance of RSNInformation.
         *
         * By default, the version is set to 1.
         */
        RSNInformation();

        /**
         * \brief Helper function to create a WPA2-PSK RSNInformation
         * \return An instance RSNInformation which contains information
         * for a WPA2-PSK AP.
         */
        static RSNInformation wpa2_psk();

        /**
         * \brief Adds a pairwise cypher suite.
         * \param cypher The pairwise cypher suite to be added.
         */
        void add_pairwise_cypher(CypherSuites cypher);

        /**
         * \brief Adds a akm suite.
         * \param akm The akm suite to be added.
         */
        void add_akm_cypher(AKMSuites akm);

        /**
         * \brief Sets the group suite cypher.
         * \param group The group suite cypher to be set.
         */
        void group_suite(CypherSuites group);

        /**
         * \brief Sets the version.
         * \param ver The version to be set.
         */
        void version(uint16_t ver);

        /**
         * \brief Sets the capabilities field.
         * \param cap The capabilities to be set.
         */
        void capabilities(uint16_t cap);

        /* Getters */

        /**
         * \brief Getter for the group suite field.
         * \return The group suite field.
         */
        inline CypherSuites group_suite() const { return _group_suite; }

        /**
         * \brief Getter for the version field.
         * \return The version field.
         */
        inline uint16_t version() const { return _version; }

        /**
         * \brief Getter for the pairwise cypher suite list.
         * \return A list of pairwise cypher suites.
         */
        inline const std::list<CypherSuites> &pairwise_cyphers() const { return _pairwise_cyphers; }

        /**
         * \brief Getter for the akm suite list.
         * \return A list of akm suites.
         */
        inline const std::list<AKMSuites> &akm_cyphers() const { return _akm_cyphers; }

        /**
         * \brief Serializes this object.
         * \param size Output parameter which will contain the size of
         * the allocated buffer.
         * \return The result of the serialization. This pointer should
         * be free'd using operator delete[].
         */
        uint8_t *serialize(uint32_t &size) const;
    private:
        uint16_t _version, _capabilities;
        CypherSuites _group_suite;
        std::list<AKMSuites> _akm_cyphers;
        std::list<CypherSuites> _pairwise_cyphers;
    };

    /**
     * \brief Abstract class that englobes all Management frames in the 802.11 protocol.
     */
    class Dot11ManagementFrame : public Dot11 {

    public:

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

        struct CapabilityInformation {
            unsigned int _ess:1;
            unsigned int _ibss:1;
            unsigned int _cf_poll:1;
            unsigned int _cf_poll_req:1;
            unsigned int _privacy:1;
            unsigned int _short_preamble:1;
            unsigned int _pbcc:1;
            unsigned int _channel_agility:1;
            unsigned int _spectrum_mgmt:1;
            unsigned int _qos:1;
            unsigned int _sst:1;
            unsigned int _apsd:1;
            unsigned int _reserved:1;
            unsigned int _dsss_ofdm:1;
            unsigned int _delayed_block_ack:1;
            unsigned int _immediate_block_ack:1;

            /**
             * \brief Getter for the ess flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool ess() const { return this->_ess; }

            /**
             * \brief Getter for the ibss flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool ibss() const { return this->_ibss; }

            /**
             * \brief Getter for the cf_poll flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool cf_poll() const { return this->_cf_poll; }

            /**
             * \brief Getter for the cf_poll_req flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool cf_poll_req() const { return this->_cf_poll_req; }

            /**
             * \brief Getter for the privacy flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool privacy() const { return this->_privacy; }

            /**
             * \brief Getter for the short_preamble flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool short_preamble() const { return this->_short_preamble; }

            /**
             * \brief Getter for the pbcc flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool pbcc() const { return this->_pbcc; }

            /**
             * \brief Getter for the channel_agility flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool channel_agility() const { return this->_channel_agility; }

            /**
             * \brief Getter for the spectrum_mgmt flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool spectrum_mgmt() const { return this->_spectrum_mgmt; }

            /**
             * \brief Getter for the qos flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool qos() const { return this->_qos; }

            /**
             * \brief Getter for the sst flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool sst() const { return this->_sst; }

            /**
             * \brief Getter for the apsd flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool apsd() const { return this->_apsd; }

            /**
             * \brief Getter for the reserved flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool reserved() const { return this->_reserved; }

            /**
             * \brief Getter for the dsss_ofdm flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool dsss_ofdm() const { return this->_dsss_ofdm; }

            /**
             * \brief Getter for the delayed_block_ack flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool delayed_block_ack() const { return this->_delayed_block_ack; }

            /**
             * \brief Getter for the immediate_block_ack flag.
             *
             * \return Bool indicating the flag's value.
             */
            inline bool immediate_block_ack() const { return this->_immediate_block_ack; }

            /**
             * \brief Setter for the ess flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void ess(bool new_value) { this->_ess = new_value; }

            /**
             * \brief Setter for the ibss flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void ibss(bool new_value) { this->_ibss = new_value; }

            /**
             * \brief Setter for the cf_poll flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void cf_poll(bool new_value) { this->_cf_poll = new_value; }

            /**
             * \brief Setter for the cf_poll_req flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void cf_poll_req(bool new_value) { this->_cf_poll_req = new_value; }

            /**
             * \brief Setter for the privacy flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void privacy(bool new_value) { this->_privacy = new_value; }

            /**
             * \brief Setter for the short_preamble flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void short_preamble(bool new_value) { this->_short_preamble = new_value; }

            /**
             * \brief Setter for the pbcc flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void pbcc(bool new_value) { this->_pbcc = new_value; }

            /**
             * \brief Setter for the channel_agility flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void channel_agility(bool new_value) { this->_channel_agility = new_value; }

            /**
             * \brief Setter for the spectrum_mgmt flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void spectrum_mgmt(bool new_value) { this->_spectrum_mgmt = new_value; }

            /**
             * \brief Setter for the qos flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void qos(bool new_value) { this->_qos = new_value; }

            /**
             * \brief Setter for the sst flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void sst(bool new_value) { this->_sst = new_value; }

            /**
             * \brief Setter for the apsd flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void apsd(bool new_value) { this->_apsd = new_value; }

            /**
             * \brief Setter for the reserved flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void reserved(bool new_value) { this->_reserved = new_value; }

            /**
             * \brief Setter for the dsss_ofdm flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void dsss_ofdm(bool new_value) { this->_dsss_ofdm = new_value; }

            /**
             * \brief Setter for the delayed_block_ack flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void delayed_block_ack(bool new_value) { this->_delayed_block_ack = new_value; }

            /**
             * \brief Setter for the immediate_block_ack flag.
             *
             * \param new_value bool indicating the flag's new value.
             */
            void immediate_block_ack(bool new_value) { this->_immediate_block_ack = new_value; }

        } __attribute__((__packed__));

        /**
         * \brief Getter for the second address.
         *
         * \return The second address as a constant uint8_t pointer.
         */
        inline const uint8_t* addr2() const { return this->_ext_header.addr2; }

        /**
         * \brief Getter for the third address.
         *
         * \return The third address as a constant uint8_t pointer.
         */
        inline const uint8_t* addr3() const { return this->_ext_header.addr3; }

        /**
         * \brief Getter for the fragment number.
         *
         * \return The fragment number as an uint8_t.
         */
        inline uint8_t frag_num() const { return this->_ext_header.seq_control.frag_number; }

        /**
         * \brief Getter for the sequence number.
         *
         * \return The sequence number as an uint16_t.
         */
        inline uint16_t seq_num() const { return Utils::net_to_host_s(this->_ext_header.seq_control.seq_number); }

        /**
         * \brief Getter for the fourth address.
         *
         * \return The fourth address as a constant uint8_t pointer.
         */
        inline const uint8_t* addr4() const { return this->_addr4; }

        /**
         * \brief Setter for the second address.
         *
         * \param new_addr2 const uint8_t array of 6 bytes containing the new second's address.
         */
        void addr2(const uint8_t* new_addr2);

        /**
         * \brief Setter for the third address.
         *
         * \param new_addr3 const uint8_t array of 6 bytes containing the new third address.
         */
        void addr3(const uint8_t* new_addr3);

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
         * \brief Setter for the fourth address.
         *
         * \param new_addr4 const uint8_t array of 6 bytes containing the new fourth address.
         */
        void addr4(const uint8_t* new_addr4);

        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
    protected:
        struct ExtendedHeader {
            uint8_t addr2[6];
            uint8_t addr3[6];
            struct {
            #if __BYTE_ORDER == __LITTLE_ENDIAN
                unsigned int seq_number:12;
                unsigned int frag_number:4;
            #elif __BYTE_ORDER == __BIG_ENDIAN
                unsigned int frag_number:4;
                unsigned int seq_number:12;
            #endif
            } __attribute__((__packed__)) seq_control;
        } __attribute__((__packed__));

        /**
         * \brief Constructor which creates a Dot11ManagementFrame object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ManagementFrame(const uint8_t *dst_hw_addr = 0, const uint8_t *src_hw_addr = 0);
        Dot11ManagementFrame(const std::string &iface, const uint8_t *dst_hw_addr, const uint8_t *src_hw_addr) throw (std::runtime_error);
        Dot11ManagementFrame(const uint8_t *buffer, uint32_t total_sz);
        Dot11ManagementFrame(const Dot11ManagementFrame &other);

        void ssid(const std::string &new_ssid);
        void rates(const std::list<float> &new_rates);
        void channel(uint8_t new_channel);
        void rsn_information(const RSNInformation& info);
        void supported_rates(const std::list<float> &new_rates);
        void extended_supported_rates(const std::list<float> &new_rates);
        void qos_capabilities(uint8_t new_qos_capabilities);
        void power_capabilities(uint8_t min_power, uint8_t max_power);
        void supported_channels(const std::list<std::pair<uint8_t, uint8_t> > &new_channels);
        void edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo);

        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);
        void copy_ext_header(const Dot11ManagementFrame *other);
    private:
        ExtendedHeader _ext_header;
        uint8_t _addr4[6];

    };

    class Dot11DataFrame : public Dot11 {
    public:
        /**
         * \brief Constructor which creates a Dot11DataFrame object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11DataFrame(uint32_t iface_index, const uint8_t *dst_hw_addr = 0, const uint8_t *src_hw_addr = 0, PDU* child = 0);
        Dot11DataFrame(const uint8_t *dst_hw_addr = 0, const uint8_t *src_hw_addr = 0, PDU* child = 0);
        Dot11DataFrame(const std::string &iface, const uint8_t *dst_hw_addr, const uint8_t *src_hw_addr, PDU* child = 0) throw (std::runtime_error);
        Dot11DataFrame(const uint8_t *buffer, uint32_t total_sz);
        Dot11DataFrame(const Dot11DataFrame &other);
        /**
         * \brief Getter for the second address.
         *
         * \return The second address as a constant uint8_t pointer.
         */
        inline const uint8_t* addr2() const { return this->_ext_header.addr2; }

        /**
         * \brief Getter for the third address.
         *
         * \return The third address as a constant uint8_t pointer.
         */
        inline const uint8_t* addr3() const { return this->_ext_header.addr3; }

        /**
         * \brief Getter for the fragment number.
         *
         * \return The fragment number as an uint8_t.
         */
        inline uint8_t frag_num() const { return this->_ext_header.seq_control.frag_number; }

        /**
         * \brief Getter for the sequence number.
         *
         * \return The sequence number as an uint16_t.
         */
        inline uint16_t seq_num() const { return Utils::net_to_host_s(this->_ext_header.seq_control.seq_number); }

        /**
         * \brief Getter for the fourth address.
         *
         * \return The fourth address as a constant uint8_t pointer.
         */
        inline const uint8_t* addr4() const { return this->_addr4; }

        /**
         * \brief Setter for the second address.
         *
         * \param new_addr2 const uint8_t array of 6 bytes containing the new second's address.
         */
        void addr2(const uint8_t* new_addr2);

        /**
         * \brief Setter for the third address.
         *
         * \param new_addr3 const uint8_t array of 6 bytes containing the new third address.
         */
        void addr3(const uint8_t* new_addr3);

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
         * \brief Setter for the fourth address.
         *
         * \param new_addr4 const uint8_t array of 6 bytes containing the new fourth address.
         */
        void addr4(const uint8_t* new_addr4);

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
        PDUType pdu_type() const { return PDU::DOT11_DATA; }
    protected:
        struct ExtendedHeader {
            uint8_t addr2[6];
            uint8_t addr3[6];
            struct {
            #if __BYTE_ORDER == __LITTLE_ENDIAN
                unsigned int seq_number:12;
                unsigned int frag_number:4;
            #elif __BYTE_ORDER == __BIG_ENDIAN
                unsigned int frag_number:4;
                unsigned int seq_number:12;
            #endif
            } __attribute__((__packed__)) seq_control;
        } __attribute__((__packed__));

        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);
        void copy_ext_header(const Dot11DataFrame *other);

    private:
        ExtendedHeader _ext_header;
        uint8_t _addr4[6];

    };

    /**
     * \brief Class representing a Beacon in the IEEE 802.11 Protocol.
     *
     */
    class Dot11Beacon : public Dot11ManagementFrame {

    public:

        /**
         * \brief Default constructor for the beacon frame.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         */
        Dot11Beacon(const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0);

        /**
         * \brief Constructor for creating a 802.11 Beacon.
         *
         * Constructor that builds a 802.11 Beacon taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         */
        Dot11Beacon(const std::string& iface, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0) throw (std::runtime_error);

        /**
         * \brief Constructor which creates a Dot11Beacon object from a buffer and adds
         * all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11Beacon(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Copy constructor.
         */
        Dot11Beacon(const Dot11Beacon &other);

        /**
         * \brief Copy assignment operator.
         */
        Dot11Beacon &operator= (const Dot11Beacon &other);

        /**
         * \brief Getter for the timestamp field.
         *
         * \return Timestamp value in an uint64_t.
         */
        inline uint64_t timestamp() const { return this->_body.timestamp; }

        /**
         * \brief Getter for the interval field.
         *
         * \return Timestamp value in an uint64_t.
         */
        inline uint16_t interval() const { return Utils::net_to_host_s(this->_body.interval); }

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline const CapabilityInformation& capabilities() const { return this->_body.capability;}

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline CapabilityInformation& capabilities() { return this->_body.capability;}

        /**
         * \brief Setter for the timestamp field.
         *
         * \param new_timestamp uint64_t with the timestamp to set.
         */
        void timestamp(uint64_t new_timestamp);

        /**
         * \brief Setter for the interval field.
         *
         * \param new_interval uint16_t with the interval to set.
         */
        void interval(uint16_t new_interval);

        /**
         * \brief Helper method to set the essid.
         * \param new_essid The essid to be set.
         */
        void essid(const std::string &new_essid);

        /**
         * \brief Helper method to set the supported rates.
         * \param new_rates A list of rates to be set.
         */
        void rates(const std::list<float> &new_rates);

        /**
         * \brief Helper method to set the current channel.
         * \param new_channel The new channel to be set.
         */
        void channel(uint8_t new_channel);

        /**
         * \brief Helper method to set the RSN information option.
         * \param info The RSNInformation structure to be set.
         */
        void rsn_information(const RSNInformation& info);

        /**
         * \brief Helper method to search for the ESSID of this beacon.
         *
         * This method returns the essid of this beacon, or an empty
         * string if no essid has been set.
         */
        std::string essid() const;

        /**
         * \brief Helper method to search for the RSN information of this beacon.
         *
         * This method fills the RSN information structure of this beacon.
         * \param rsn A pointer in which the RSN information will be stored.
         * \return True if the RSNInformation option has been set.
         */
        bool rsn_information(RSNInformation *rsn);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
    private:
        struct BeaconBody {
            uint64_t timestamp;
            uint16_t interval;
            CapabilityInformation capability;
        } __attribute__((__packed__));

        void copy_fields(const Dot11Beacon *other);
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
         * \brief Default constructor for the Disassociation frame.
         *
         */
        Dot11Disassoc();

        /**
         * \brief Constructor for creating a 802.11 Disassociation.
         *
         * Constructor that builds a 802.11 Disassociation taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         */
        Dot11Disassoc(const std::string& iface, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0) throw (std::runtime_error);

        /**
         * \brief Copy constructor.
         */
        Dot11Disassoc(const Dot11Disassoc &other);

        /**
         * \brief Copy assignment operator.
         */
        Dot11Disassoc &operator= (const Dot11Disassoc &other);

        /**
         * \brief Getter for the reason code.
         *
         * \return uint16_t with the reason code.
         */
        inline uint16_t reason_code() const { return this->_body.reason_code; }

        /**
         * \brief Setter for the reason code.
         *
         * \param new_reason_code uint16_t with the new reason code.
         */
        void reason_code(uint16_t new_reason_code);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
    private:
        struct DisassocBody {
            uint16_t reason_code;
        };

        void copy_fields(const Dot11Disassoc *other);
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
         * \brief Default constructor for the Association Request frame.
         *
         */
        Dot11AssocRequest();

        /**
         * \brief Constructor for creating a 802.11 Association Request.
         *
         * Constructor that builds a 802.11 Association Request taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         */
        Dot11AssocRequest(const std::string& iface, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0) throw (std::runtime_error);

        /**
         * \brief Constructor which creates a Dot11AssocRequest object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11AssocRequest(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Copy constructor.
         */
        Dot11AssocRequest(const Dot11AssocRequest &other);

        /**
         * \brief Copy assignment operator.
         */
        Dot11AssocRequest &operator= (const Dot11AssocRequest &other);

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline const CapabilityInformation& capabilities() const { return this->_body.capability;}

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline CapabilityInformation& capabilities() { return this->_body.capability;}

        /**
         * \brief Getter for the listen interval.
         *
         * \return The listen interval in an uint16_t.
         */
        inline uint16_t listen_interval() const { return this->_body.listen_interval; }

        /**
         * \brief Setter for the listen interval.
         *
         * \param new_listen_interval uint16_t with the new listen interval.
         */
        void listen_interval(uint16_t new_listen_interval);

        /**
         * \brief Helper method to set the essid.
         *
         * \param new_ssid The ssid to be set.
         */
        void ssid(const std::string &new_ssid);

        /**
         * \brief Helper method to set the supported rates.
         *
         * \param new_rates A list of rates to be set.
         */
        void supported_rates(const std::list<float> &new_rates);

        /**
         * \brief Helper method to set the extended supported rates.
         *
         * \param new_rates A list of rates to be set.
         */
        void extended_supported_rates(const std::list<float> &new_rates);

        /**
         * \brief Helper method to set the power capabilities.
         *
         * \param min_power uint8_t indicating the minimum transmiting power capability.
         * \param max_power uint8_t indicating the maximum transmiting power capability.
         */
        void power_capabilities(uint8_t min_power, uint8_t max_power);

        /**
         * \brief Helper method to set the supported channels.
         *
         * \param new_channels A list of channels to be set.
         */
        void supported_channels(const std::list<std::pair<uint8_t, uint8_t> > &new_channels);

        /**
         * \brief Helper method to set the RSN information option.
         *
         * \param info The RSNInformation structure to be set.
         */
        void rsn_information(const RSNInformation& info);

        /**
         * \brief Helper method to set the QoS capabilities.
         *
         * \param new_qos_capabilities uint8_t with the capabilities.
         */
        void qos_capabilities(uint8_t new_qos_capabilities);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
    private:
        struct AssocReqBody {
            CapabilityInformation capability;
            uint16_t listen_interval;
        };

        void copy_fields(const Dot11AssocRequest *other);
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
         * \brief Default constructor for the Association Response frame.
         *
         */
        Dot11AssocResponse();

        /**
         * \brief Constructor for creating a 802.11 Association Response.
         *
         * Constructor that builds a 802.11 Association Response taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         */
        Dot11AssocResponse(const std::string& iface, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0) throw (std::runtime_error);

        /**
         * \brief Constructor which creates a Dot11AssocResponse object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11AssocResponse(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Copy constructor.
         */
        Dot11AssocResponse(const Dot11AssocResponse &other);

        /**
         * \brief Copy assignment operator
         */
        Dot11AssocResponse &operator= (const Dot11AssocResponse &other);

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline const CapabilityInformation& capabilities() const { return this->_body.capability;}

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline CapabilityInformation& capabilities() { return this->_body.capability;}

        /**
         * \brief Getter for the status code.
         *
         * \return The status code in an uint16_t.
         */
        inline uint16_t status_code() const { return this->_body.status_code; }

        /**
         * \brief Getter for the AID field.
         *
         * \return The AID field value in an uint16_t.
         */
        inline uint16_t aid() const { return this->_body.aid; }

        /**
         * \brief Setter for the status code.
         *
         * \param new_status_code uint16_t with the new status code.
         */
        void status_code(uint16_t new_status_code);

        /**
         * \brief Setter for the AID field.
         *
         * \param new_aid uint16_t with the new AID value.
         */
        void aid(uint16_t new_aid);

        /**
         * \brief Helper method to set the supported rates.
         *
         * \param new_rates A list of rates to be set.
         */
        void supported_rates(const std::list<float> &new_rates);

        /**
         * \brief Helper method to set the extended supported rates.
         *
         * \param new_rates A list of rates to be set.
         */
        void extended_supported_rates(const std::list<float> &new_rates);

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
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;
    private:
        struct AssocRespBody {
            CapabilityInformation capability;
            uint16_t status_code;
            uint16_t aid;
        };

        void copy_fields(const Dot11AssocResponse *other);
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
         * \brief Default constructor for the ReAssociation Request frame.
         *
         */
        Dot11ReAssocRequest();

        /**
         * \brief Constructor for creating a 802.11 ReAssociation Request.
         *
         * Constructor that builds a 802.11 ReAssociation Request taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         */
        Dot11ReAssocRequest(const std::string& iface, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0) throw (std::runtime_error);

        /**
         * \brief Constructor which creates a Dot11ReAssocRequest object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ReAssocRequest(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Copy constructor.
         */
        Dot11ReAssocRequest(const Dot11ReAssocRequest &other);

        /**
         * \brief Copy assignment operator.
         */
        Dot11ReAssocRequest &operator= (const Dot11ReAssocRequest &other);

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline const CapabilityInformation& capabilities() const { return this->_body.capability;}

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline CapabilityInformation& capabilities() { return this->_body.capability;}

        /**
         * \brief Getter for the listen interval.
         *
         * \return The listen interval in an uint16_t.
         */
        inline uint16_t listen_interval() const { return this->_body.listen_interval; }

        /**
         * \brief Getter for the current AP field.
         *
         * \return The current AP value in an uint8_t*.
         */
        inline const uint8_t* current_ap() const {return this->_body.current_ap; }

        /**
         * \brief Setter for the listen interval.
         *
         * \param new_listen_interval uint16_t with the new listen interval.
         */
        void listen_interval(uint16_t new_listen_interval);

        /**
         * \brief Setter for the current AP field.
         *
         * \param new_current_ap uint8_t array of 6 bytes with the new current_ap
         */
        void current_ap(const uint8_t* new_current_ap);

        /**
         * \brief Helper method to set the essid.
         *
         * \param new_ssid The ssid to be set.
         */
        void ssid(const std::string &new_ssid);

        /**
         * \brief Helper method to set the supported rates.
         *
         * \param new_rates A list of rates to be set.
         */
        void supported_rates(const std::list<float> &new_rates);

        /**
         * \brief Helper method to set the extended supported rates.
         *
         * \param new_rates A list of rates to be set.
         */
        void extended_supported_rates(const std::list<float> &new_rates);

        /**
         * \brief Helper method to set the power capabilities.
         *
         * \param min_power uint8_t indicating the minimum transmiting power capability.
         * \param max_power uint8_t indicating the maximum transmiting power capability.
         */
        void power_capabilities(uint8_t min_power, uint8_t max_power);

        /**
         * \brief Helper method to set the supported channels.
         *
         * \param new_channels A list of channels to be set.
         */
        void supported_channels(const std::list<std::pair<uint8_t, uint8_t> > &new_channels);

        /**
         * \brief Helper method to set the RSN information option.
         *
         * \param info The RSNInformation structure to be set.
         */
        void rsn_information(const RSNInformation& info);

        /**
         * \brief Helper method to set the QoS capabilities.
         *
         * \param new_qos_capabilities uint8_t with the capabilities.
         */
        void qos_capabilities(uint8_t new_qos_capabilities);

        /**
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;


    protected:



    private:
        struct ReAssocReqBody {
            CapabilityInformation capability;
            uint16_t listen_interval;
            uint8_t current_ap[6];
        };

        void copy_fields(const Dot11ReAssocRequest* other);
        uint32_t write_fixed_parameters(uint8_t* buffer, uint32_t total_sz);

        ReAssocReqBody _body;

    };

    /**
     * \brief Class representing an ReAssociation Response frame in the IEEE 802.11 Protocol.
     *
     */
    class Dot11ReAssocResponse : public Dot11ManagementFrame {

    public:
        /**
         * \brief Default constructor for the Association Response frame.
         *
         */
        Dot11ReAssocResponse();

        /**
         * \brief Constructor for creating a 802.11 ReAssociation Response.
         *
         * Constructor that builds a 802.11 ReAssociation Response taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         */
        Dot11ReAssocResponse(const std::string& iface, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0) throw (std::runtime_error);

        /**
         * \brief Constructor which creates a Dot11ReAssocResponse object from a
         * buffer and adds all identifiable PDUs found in the buffer as children of this one.
         *
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ReAssocResponse(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Copy constructor.
         */
        Dot11ReAssocResponse(const Dot11ReAssocResponse &other);

        /**
         * \brief Copy assignment operator
         */
        Dot11ReAssocResponse &operator= (const Dot11ReAssocResponse &other);

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline const CapabilityInformation& capabilities() const { return this->_body.capability;}

        /**
         * \brief Getter for the Capabilities Information.
         *
         * \return CapabilityInformation Structure in a CapabilityInformation&.
         */
        inline CapabilityInformation& capabilities() { return this->_body.capability;}

        /**
         * \brief Getter for the status code.
         *
         * \return The status code in an uint16_t.
         */
        inline uint16_t status_code() const { return this->_body.status_code; }

        /**
         * \brief Getter for the AID field.
         *
         * \return The AID field value in an uint16_t.
         */
        inline uint16_t aid() const { return this->_body.aid; }

        /**
         * \brief Setter for the status code.
         *
         * \param new_status_code uint16_t with the new status code.
         */
        void status_code(uint16_t new_status_code);

        /**
         * \brief Setter for the AID field.
         *
         * \param new_aid uint16_t with the new AID value.
         */
        void aid(uint16_t new_aid);

        /**
         * \brief Helper method to set the supported rates.
         *
         * \param new_rates A list of rates to be set.
         */
        void supported_rates(const std::list<float> &new_rates);

        /**
         * \brief Helper method to set the extended supported rates.
         *
         * \param new_rates A list of rates to be set.
         */
        void extended_supported_rates(const std::list<float> &new_rates);

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
         * \brief Returns the frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;


    protected:

    private:

        struct ReAssocRespBody {
            CapabilityInformation capability;
            uint16_t status_code;
            uint16_t aid;
        };

        void copy_fields(const Dot11ReAssocResponse *other);
        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

        ReAssocRespBody _body;

    };

    class Dot11QoSData : public Dot11DataFrame {

    public:

        /**
         * \brief Constructor for creating a 802.11 QoS Data PDU
         *
         * Constructor that builds a 802.11 QoS Data PDU taking the destination's and source's MAC.
         *
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11QoSData(const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 QoS Data PDU
         *
         * Constructor that builds a 802.11 QoS Data PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11QoSData(const std::string& iface, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 QoS Data PDU
         *
         * Constructor that builds an 802.11 QoS Data PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11QoSData(uint32_t iface_index, const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 QoS Data object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11QoSData(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Copy constructor.
         */
        Dot11QoSData(const Dot11QoSData &other);

        /**
         * \brief Copy assignment operator.
         */
        Dot11QoSData &operator= (const Dot11QoSData &other);

        /**
         * \brief Getter for the qos_control field.
         *
         * \return The value of the qos_control field in an uint16_t.
         */
        inline uint16_t qos_control() const { return this->_qos_control; }

        /**
         * \brief Setter for the qos_control field.
         *
         * \param new_qos_control uint16_t with the value to the the qos_control field to.
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
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::DOT11_QOS_DATA; }
    private:
        void copy_fields(const Dot11QoSData *other);
        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);


        uint16_t _qos_control;
    };

    /**
     * \brief Class that represents an 802.11 control frame.
     */
    class Dot11Control : public Dot11 {
    public:
        /**
         * \brief Constructor for creating a 802.11 control frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         *
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11Control(const uint8_t* dst_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 control frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11Control(const std::string& iface, const uint8_t* dst_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 control frame PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11Control(uint32_t iface_index, const uint8_t* dst_addr = 0, PDU* child = 0);

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
    };

    /**
     * \brief Class that represents an abstraction of the 802.11 control frames
     * that contain a target address.
     */
    class Dot11ControlTA : public Dot11Control {
    protected:
        /**
         * \brief Constructor for creating a 802.11 control frame TA PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         *
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11ControlTA(const uint8_t* dst_addr = 0, const uint8_t* target_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 control frame TA PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11ControlTA(const std::string& iface, const uint8_t* dst_addr = 0, const uint8_t *target_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 control frame TA PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11ControlTA(uint32_t iface_index, const uint8_t* dst_addr = 0, const uint8_t *target_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 control frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11ControlTA(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the target address field.
         */
        inline const uint8_t* target_addr() const { return _taddr; }

        /**
         * \brief Setter for the target address field.
         * \param addr The new target address.
         */
        void target_addr(const uint8_t *addr);

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
        uint32_t controlta_size() const { return sizeof(_taddr) + sizeof(ieee80211_header); }

        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);
    private:

        uint8_t _taddr[6];
    };

    class Dot11RTS : public Dot11ControlTA {
    public:
        /**
         * \brief Constructor for creating a 802.11 RTS frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         *
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11RTS(const uint8_t* dst_addr = 0, const uint8_t* target_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 RTS frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11RTS(const std::string& iface, const uint8_t* dst_addr = 0, const uint8_t *target_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 RTS frame PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11RTS(uint32_t iface_index, const uint8_t* dst_hw_addr = 0, const uint8_t *target_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor which creates an 802.11 RTS frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11RTS(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::DOT11_RTS; }
    };

    class Dot11PSPoll : public Dot11ControlTA {
    public:
        /**
         * \brief Constructor for creating a 802.11 PS-Poll frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         *
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11PSPoll(const uint8_t* dst_addr = 0, const uint8_t* target_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 PS-Poll frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11PSPoll(const std::string& iface, const uint8_t* dst_addr = 0, const uint8_t *target_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 PS-Poll frame PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11PSPoll(uint32_t iface_index, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child);

        /**
         * \brief Constructor which creates an 802.11 PS-Poll frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11PSPoll(const uint8_t *buffer, uint32_t total_sz);
    };

    class Dot11CFEnd : public Dot11ControlTA {
    public:
        /**
         * \brief Constructor for creating a 802.11 CF-End frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         *
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11CFEnd(const uint8_t* dst_addr = 0, const uint8_t* target_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 CF-End frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11CFEnd(const std::string& iface, const uint8_t* dst_addr = 0, const uint8_t *target_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 CF-End frame PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11CFEnd(uint32_t iface_index, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child);

        /**
         * \brief Constructor which creates an 802.11 CF-End frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11CFEnd(const uint8_t *buffer, uint32_t total_sz);
    };

    class Dot11EndCFAck : public Dot11ControlTA {
    public:
        /**
         * \brief Constructor for creating a 802.11 End-CF-Ack frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11EndCFAck(const uint8_t* dst_addr = 0, const uint8_t* target_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 End-CF-Ack frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11EndCFAck(const std::string& iface, const uint8_t* dst_addr = 0, const uint8_t *target_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 End-CF-Ack frame PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11EndCFAck(uint32_t iface_index, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child);

        /**
         * \brief Constructor which creates an 802.11 End-CF-Ack frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11EndCFAck(const uint8_t *buffer, uint32_t total_sz);
    };

    class Dot11Ack : public Dot11Control {
    public:
        /**
         * \brief Constructor for creating a 802.11 Ack frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         *
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11Ack(const uint8_t* dst_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 Ack frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         *
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11Ack(const std::string& iface, const uint8_t* dst_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 Ack frame PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         *
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11Ack(uint32_t iface_index, const uint8_t* dst_addr, PDU* child);

        /**
         * \brief Constructor which creates an 802.11 Ack frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11Ack(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::DOT11_ACK; }
    };

    /**
     * \brief Class that represents an 802.11 Block Ack Request PDU.
     */
    class Dot11BlockAckRequest : public Dot11ControlTA {
    public:
        /**
         * \brief Constructor for creating a 802.11 Block Ack request frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11BlockAckRequest(const uint8_t* dst_addr = 0, const uint8_t* target_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 Block Ack request frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11BlockAckRequest(const std::string& iface, const uint8_t* dst_addr = 0, const uint8_t *target_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 Block Ack request frame PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11BlockAckRequest(uint32_t iface_index, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child);

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
         * \return The bar control field.
         */
        uint16_t bar_control() const { return _bar_control.tid; }
        
        /**
         * \brief Getter for the start sequence field.
         * \return The bar start sequence.
         */
        uint16_t start_sequence() const { return (_start_sequence.frag << 12) | (_start_sequence.seq); }
        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /* Setter */

        /**
         * \brief Setter for the bar control field.
         * \param bar The new bar control field.
         */
        void bar_control(uint16_t bar);

        /**
         * \brief Setter for the start sequence field.
         * \param bar The new start sequence field.
         */
        void start_sequence(uint16_t seq);
    protected:
        /**
         * \brief Getter for the control ta additional fields size.
         */
        uint32_t blockack_request_size() const { return controlta_size() + sizeof(_bar_control) + sizeof(_start_sequence); }

        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);
    private:
        struct BarControl {
            uint16_t reserved:12,
                tid:4;
        } __attribute__((__packed__));

        struct StartSequence {
            uint16_t frag:4,
                seq:12;
        } __attribute__((__packed__));

        void init_block_ack();

        BarControl _bar_control;
        StartSequence _start_sequence;
    };

    /**
     * \brief Class that represents an 802.11 block ack frame.
     */
    class Dot11BlockAck : public Dot11BlockAckRequest {
    public:
        /**
         * \brief Constructor for creating a 802.11 Block Ack frame PDU.
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11BlockAck(const uint8_t* dst_addr = 0, const uint8_t* target_addr = 0, PDU* child = 0);

        /**
         * \brief Constructor for creating a 802.11 Block Ack frame PDU
         *
         * Constructor that builds a 802.11 PDU taking the interface name,
         * destination's and source's MAC.
         * \param iface string containing the interface's name from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11BlockAck(const std::string& iface, const uint8_t* dst_addr = 0, const uint8_t *target_addr = 0, PDU* child = 0) throw (std::runtime_error);

        /**
         * \brief Constructor for creating an 802.11 Block Ack frame PDU
         *
         * Constructor that builds an 802.11 PDU taking the interface index,
         * destination's and source's MAC.
         * \param iface_index const uint32_t with the interface's index from where to send the packet.
         * \param dst_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param target_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        Dot11BlockAck(uint32_t iface_index, const uint8_t* dst_addr, const uint8_t *target_addr, PDU* child);

        /**
         * \brief Constructor which creates an 802.11 Block Ack request frame object from a buffer and
         * adds all identifiable PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        Dot11BlockAck(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Returns the 802.11 frame's header length.
         *
         * \return An uint32_t with the header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the bitmap field.
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
        PDUType pdu_type() const { return PDU::DOT11_BLOCK_ACK; }
    private:
        uint32_t write_ext_header(uint8_t *buffer, uint32_t total_sz);

        uint8_t _bitmap[8];
    };
};



#endif
