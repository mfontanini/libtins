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

#if !defined(TINS_DOT11_DOT11_H) && defined(TINS_HAVE_DOT11)
#define TINS_DOT11_DOT11_H

#include <tins/pdu.h>
#include <tins/pdu_option.h>
#include <tins/small_uint.h>
#include <tins/hw_address.h>
#include <tins/endianness.h>
#include <tins/cxxstd.h>
#include <tins/macros.h>

namespace Tins {
namespace Memory {
class InputMemoryStream;
class OutputMemoryStream;
} // Memory

class RSNInformation;

/**
 * \brief Class representing an 802.11 frame.
 */
class TINS_API Dot11 : public PDU {
public:
    /**
     * The type used to store hardware addresses.
     */
    typedef HWAddress<6> address_type;

    /**
     * \brief IEEE 802.11 options struct.
     */
    typedef PDUOption<uint8_t, Dot11> option;

    /**
     * The type used to store tagged options.
     */
    typedef std::vector<option> options_type;

    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11;

    /**
     * \brief Broadcast hardware address.
     */
    static const address_type BROADCAST;

    /**
     * The endianness used by Dot11.
     */
    static const endian_type endianness = LE;

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
    enum OptionTypes {
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
        EXT_SUPPORTED_RATES = 50,
        VENDOR_SPECIFIC = 221
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
     * \brief Constructs an 802.11 PDU.
     *
     * \param dst_hw_addr The destination hardware address.
     */
    Dot11(const address_type& dst_hw_addr = address_type());

    /**
     * \brief Constructs 802.11 PDU from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for a 802.11 header in the 
     * buffer, a malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the protocol version field.
     *
     * \return The stored protocol version field.
     */
    small_uint<2> protocol() const {
        return header_.control.protocol;
    }

    /**
     * \brief Getter for the Type field.
     *
     * \return The stored Type field.
     */
    small_uint<2> type() const {
        return header_.control.type;
    }

    /**
     * \brief Getter for the Subtype field.
     *
     * \return The stored Subtype field.
     */
    small_uint<4> subtype() const {
        return header_.control.subtype;
    }

    /**
     * \brief Getter for the To-DS field.
     *
     * \return The stored To-DS field.
     */
    small_uint<1> to_ds() const {
        return header_.control.to_ds;
    }

    /**
     * \brief Getter for the From-DS field.
     *
     * \return The stored From-DS field.
     */
    small_uint<1> from_ds() const {
        return header_.control.from_ds;
    }

    /**
     * \brief Getter for the More-Frag field.
     *
     * \return The stored More-Frag field.
     */
    small_uint<1> more_frag() const {
        return header_.control.more_frag;
    }

    /**
     * \brief Getter for the Retry field.
     *
     * \return The stored Retry field.
     */
    small_uint<1> retry() const {
        return header_.control.retry;
    }

    /**
     * \brief Getter for the Power-Management field.
     *
     * \return The stored Power-Management field.
     */
    small_uint<1> power_mgmt() const {
        return header_.control.power_mgmt;
    }

    /**
     * \brief Getter for the More Data field.
     *
     * \return The stored More Data field.
     */
    small_uint<1> more_data() const {
        return header_.control.more_data;
    }

    /**
     * \brief Getter for the WEP field.
     *
     * \return The stored WEP field.
     */
    small_uint<1> wep() const {
        return header_.control.wep;
    }

    /**
     * \brief Getter for the Order field.
     *
     * \return The stored Order field.
     */
    small_uint<1> order() const {
        return header_.control.order;
    }

    /**
     * \brief Getter for the Duration-ID field.
     *
     * \return The stored Duration-ID field.
     */
    uint16_t duration_id() const {
        return Endian::le_to_host(header_.duration_id);
    }

    /**
     * \brief Getter for the first address.
     *
     * \return The stored first address.
     */
    address_type addr1() const {
        return header_.addr1;
    }

    // Setters

    /**
     * \brief Setter for the protocol version field.
     *
     * \param new_proto The new protocol version field value.
     */
    void protocol(small_uint<2> new_proto);

    /**
     * \brief Setter for the type field.
     *
     * \param new_type The new type field value.
     */
    void type(small_uint<2> new_type);

    /**
     * \brief Setter for the subtype field.
     *
     * \param new_subtype The new subtype field value.
     */
    void subtype(small_uint<4> new_subtype);

    /**
     * \brief Setter for the To-DS field.
     *
     * \param new_value The new To-DS field value.
     */
    void to_ds(small_uint<1> new_value);

    /**
     * \brief Setter for the From-DS field.
     *
     * \param new_value The new From-DS field value.
     */
    void from_ds(small_uint<1> new_value);

    /**
     * \brief Setter for the More-Frag field.
     *
     * \param new_value The new More-Frag field value.
     */
    void more_frag(small_uint<1> new_value);

    /**
     * \brief Setter for the Retry field.
     *
     * \param new_value The new Retry field value.
     */
    void retry(small_uint<1> new_value);

    /**
     * \brief Setter for the Power-Management field.
     *
     * \param new_value The new Power-Management field value.
     */
    void power_mgmt(small_uint<1> new_value);

    /**
     * \brief Setter for the More Data field.
     *
     * \param new_value The new More Data field value.
     */
    void more_data(small_uint<1> new_value);

    /**
     * \brief Setter for the WEP field.
     *
     * \param new_value The new WEP field value.
     */
    void wep(small_uint<1> new_value);

    /**
     * \brief Setter for the Order field.
     *
     * \param new_value The new Order field value.
     */
    void order(small_uint<1> new_value);

    /**
     * \brief Setter for the Duration-ID field.
     *
     * \param new_duration_id The new Duration-ID field value.
     */
    void duration_id(uint16_t new_duration_id);

    /**
     * \brief Setter for the first address.
     *
     * \param new_addr1 The new first address.
     */
    void addr1(const address_type& new_addr1);

    /* Virtual methods */
    /**
     * \brief Returns the 802.11 frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;
    
    #ifndef _WIN32
    /**
     * \sa PDU::send()
     */
    void send(PacketSender& sender, const NetworkInterface& iface);
    #endif // _WIN32
    
    /**
     * \brief Adds a new option to this Dot11 PDU.
     * \param opt The option to be added.
     */
    void add_option(const option& opt);
    
    #if TINS_IS_CXX11
        /**
         * \brief Adds a new option to this Dot11 PDU.
         * 
         * The option is move-constructed
         * 
         * \param opt The option to be added.
         */
        void add_option(option &&opt) {
            internal_add_option(opt);
            options_.push_back(std::move(opt));
        }
    #endif

    /**
     * \brief Removes a Dot11 option.
     * 
     * If there are multiple options of the given type, only the first one
     * will be removed.
     *
     * \param type The type of the option to be removed.
     * \return true if the option was removed, false otherwise.
     */
    bool remove_option(OptionTypes type);

    /**
     * \brief Looks up a tagged option in the option list.
     * 
     * The returned pointer <b>must not</b> be free'd.
     * 
     * \param type The option identifier.
     * \return The option found, or 0 if no such option has been set.
     */
    const option* search_option(OptionTypes type) const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }
    
    /**
     * \sa PDU::clone
     */
    Dot11* clone() const {
        return new Dot11(*this);
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag;
    }
    
    /**
     * \brief Getter for the option list.
     * 
     * \return The options list.
     */
    const options_type& options() const {
        return options_;
    }

    /**
     * \brief Allocates an Dot11 PDU from a buffer.
     * 
     * This can be used somehow as a "virtual constructor". This 
     * method instantiates the appropriate subclass of Dot11 from the 
     * given buffer.
     * 
     * The allocated class' type will be figured out from the
     * information provided in the buffer.
     * 
     * \param buffer The buffer from which to take the PDU data.
     * \param total_sz The total size of the buffer.
     * \return The allocated Dot11 PDU.
     */
    static Dot11* from_bytes(const uint8_t* buffer, uint32_t total_sz);
protected:
    virtual void write_ext_header(Memory::OutputMemoryStream& stream);
    virtual void write_fixed_parameters(Memory::OutputMemoryStream& stream);
    void parse_tagged_parameters(Memory::InputMemoryStream& stream);
    void add_tagged_option(OptionTypes opt, uint8_t len, const uint8_t* val);
protected:
    /**
     * Struct that represents the 802.11 header
     */
    TINS_BEGIN_PACK
    struct dot11_header {
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
    Dot11(const dot11_header* header_ptr);
    
    void internal_add_option(const option& opt);
    void write_serialization(uint8_t* buffer, uint32_t total_sz);
    options_type::const_iterator search_option_iterator(OptionTypes type) const;
    options_type::iterator search_option_iterator(OptionTypes type);


    dot11_header header_;
    uint32_t options_size_;
    options_type options_;
};

} // Tins

#endif // TINS_DOT11_DOT11_H
