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

#include <list>
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
            PS = 10,
            RTS = 11,
            CTS = 12,
            ACK = 13,
            CF = 14,
            CFE_CFA = 15
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
            CF_ACK_POLL = 7
        };

        /**
         * \brief IEEE 802.11 options struct.
         */
        struct IEEE802_11_Option {
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
             * \brief Creates an instance of IEEE802_11_Option.
             *
             * The option's value is copied, therefore the user should
             * manually free any memory pointed by the "val" parameter.
             * \param opt The option number.
             * \param len The length of the option's value in bytes.
             * \param val The option's value.
             */
            IEEE802_11_Option(uint8_t opt, uint8_t len, const uint8_t *val);
        };

        /**
         * \brief Constructor for creating a 802.11 PDU
         *
         * Constructor that builds a 802.11 PDU taking the destination's and source's MAC.
         *
         * \param dst_hw_addr uint8_t array of 6 bytes containing the destination's MAC(optional).
         * \param src_hw_addr uint8_t array of 6 bytes containing the source's MAC(optional).
         * \param child PDU* with the PDU contained by the 802.11 PDU (optional).
         */
        IEEE802_11(const uint8_t* dst_hw_addr = 0, const uint8_t* src_hw_addr = 0, PDU* child = 0);

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
         * \brief IEEE802_11 destructor.
         *
         * Releases the memory allocated for tagged options.
         */
        ~IEEE802_11();

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
        inline const uint8_t* opt_addr() const { return this->_opt_addr; }

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
         * \brief Adds a new option to this IEEE802_11 PDU.
         *
         * This copies the value buffer.
         * \param opt The option identifier.
         * \param len The length of the value field.
         * \param val The value of this option.
         */
        void add_tagged_option(TaggedOption opt, uint8_t len, const uint8_t *val);

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::IEEE802_11; }
    protected:
        virtual uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz) { return 0; }
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

        } __attribute__((__packed__));

        IEEE802_11(const ieee80211_header *header_ptr);

        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);


        ieee80211_header _header;
        uint8_t _opt_addr[6];
        uint32_t _iface_index, _options_size;
        std::list<IEEE802_11_Option> _options;
    };


    /**
     * \brief Abstract class that englobes all Management frames in the 802.11 protocol.
     */
    class ManagementFrame : public IEEE802_11 {

    public:

    protected:

        ManagementFrame();

        struct CapabilityInformation {
            unsigned int ess:1;
            unsigned int ibss:1;
            unsigned int cf_poll:1;
            unsigned int cf_poll_req:1;
            unsigned int privacy:1;
            unsigned int short_preamble:1;
            unsigned int pbcc:1;
            unsigned int chanel_agility:1;
            unsigned int spectrum_mgmt:1;
            unsigned int qos:1;
            unsigned int sst:1;
            unsigned int apsd:1;
            unsigned int reserved:1;
            unsigned int dsss_ofdm:1;
            unsigned int delayed_block_ack:1;
            unsigned int immediate_block_ack:1;
        } __attribute__((__packed__));

    private:


    };

    /**
     * \brief Class representing a Beacon in the IEEE 802.11 Protocol.
     *
     */
    class IEEE802_11_Beacon : public ManagementFrame {

    public:

        /**
         * \brief Default constructor for the beacon frame.
         *
         */
        IEEE802_11_Beacon();

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

        BeaconBody _body;

        uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

    };



}

#endif
