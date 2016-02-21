/*
 * Copyright (c) 2016, Matias Fontanini
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

#ifndef TINS_DHCPV6_H
#define TINS_DHCPV6_H

#include <cstring>
#include <list>
#include "pdu.h"
#include "macros.h"
#include "endianness.h"
#include "small_uint.h"
#include "ipv6_address.h"
#include "pdu_option.h"

namespace Tins {
namespace Memory  {

class OutputMemoryStream;

} // Memory

/**
 * \class DHCPv6
 * \brief Represents a DHCPv6 PDU.
 */
class TINS_API DHCPv6 : public PDU {
public:
    /**
     * Represents a DHCPv6 option. 
     */
    typedef PDUOption<uint16_t, DHCPv6> option;

    /**
     * The message types.
     */
    enum MessageType {
        SOLICIT = 1,
        ADVERTISE,
        REQUEST,
        CONFIRM,
        RENEW,
        REBIND,
        REPLY,
        RELEASE,
        DECLINE,
        RECONFIGURE,
        INFO_REQUEST,
        RELAY_FORWARD,
        RELAY_REPLY,
        LEASE_QUERY,
        LEASE_QUERY_REPLY,
        LEASE_QUERY_DONE,
        LEASE_QUERY_DATA
    };
    
    /**
     * The DHCPv6 options.
     */
    enum OptionTypes {
        CLIENTID = 1, 
        SERVERID, 
        IA_NA, 
        IA_TA, 
        IA_ADDR, 
        OPTION_REQUEST, 
        PREFERENCE, 
        ELAPSED_TIME, 
        RELAY_MSG, 
        AUTH = 11, 
        UNICAST, 
        STATUS_CODE, 
        RAPID_COMMIT, 
        USER_CLASS, 
        VENDOR_CLASS, 
        VENDOR_OPTS, 
        INTERFACE_ID, 
        RECONF_MSG, 
        RECONF_ACCEPT, 
        SIP_SERVER_D, 
        SIP_SERVER_A, 
        DNS_SERVERS, 
        DOMAIN_LIST, 
        IA_PD, 
        IAPREFIX, 
        NIS_SERVERS, 
        NISP_SERVERS, 
        NIS_DOMAIN_NAME, 
        NISP_DOMAIN_NAME, 
        SNTP_SERVERS, 
        INFORMATION_REFRESH_TIME, 
        BCMCS_SERVER_D, 
        BCMCS_SERVER_A, 
        GEOCONF_CIVIC = 36, 
        REMOTE_ID, 
        SUBSCRIBER_ID, 
        CLIENT_FQDN, 
        PANA_AGENT, 
        NEW_POSIX_TIMEZONE, 
        NEW_TZDB_TIMEZONE, 
        ERO, 
        LQ_QUERY, 
        CLIENT_DATA, 
        CLT_TIME, 
        LQ_RELAY_DATA, 
        LQ_CLIENT_LINK, 
        MIP6_HNIDF, 
        MIP6_VDINF, 
        V6_LOST, 
        CAPWAP_AC_V6, 
        RELAY_ID, 
        NTP_SERVER, 
        V6_ACCESS_DOMAIN, 
        SIP_UA_CS_LIST, 
        BOOTFILE_URL, 
        BOOTFILE_PARAM, 
        CLIENT_ARCH_TYPE, 
        NII, 
        GEOLOCATION, 
        AFTR_NAME, 
        ERP_LOCAL_DOMAIN_NAME, 
        RSOO, 
        PD_EXCLUDE, 
        VSS, 
        MIP6_IDINF, 
        MIP6_UDINF, 
        MIP6_HNP, 
        MIP6_HAA, 
        MIP6_HAF, 
        RDNSS_SELECTION, 
        KRB_PRINCIPAL_NAME, 
        KRB_REALM_NAME, 
        KRB_DEFAULT_REALM_NAME, 
        KRB_KDC
    };

    /**
     * The type used to store the DHCPv6 options.
     */
    typedef std::list<option> options_type;

    /**
     * The type used to store IP addresses.
     */
    typedef IPv6Address ipaddress_type;
    
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DHCPv6;

    /**
     * The type used to store the Identity Association for Non-Temporary
     * Addresses option.
     */
    struct ia_na_type {
        typedef std::vector<uint8_t> options_type;
        
        uint32_t id, t1, t2;
        options_type options;
        
        ia_na_type(uint32_t id = 0, uint32_t t1 = 0, uint32_t t2 = 0,
          const options_type& options = options_type())
        : id(id), t1(t1), t2(t2), options(options) {}

        static ia_na_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the Identity Association for Temporary
     * Addresses option.
     */
    struct ia_ta_type {
        typedef std::vector<uint8_t> options_type;
        
        uint32_t id;
        options_type options;
        
        ia_ta_type(uint32_t id = 0,
          const options_type& options = options_type())
        : id(id), options(options) {}

        static ia_ta_type from_option(const option& opt);
    };

    /**
     * The type used to store the Identity Association Address option.
     */
    struct ia_address_type {
        typedef std::vector<uint8_t> options_type;
        
        ipaddress_type address;
        uint32_t preferred_lifetime, valid_lifetime;
        options_type options;
        
        ia_address_type(ipaddress_type address = ipaddress_type(), 
          uint32_t preferred_lifetime = 0, uint32_t valid_lifetime = 0, 
          const options_type& options = options_type())
        : address(address), preferred_lifetime(preferred_lifetime), 
          valid_lifetime(valid_lifetime), options(options) {}

        static ia_address_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the Authentication option.
     */
    struct authentication_type {
        typedef std::vector<uint8_t> auth_info_type;
        
        uint8_t protocol, algorithm, rdm;
        uint64_t replay_detection;
        auth_info_type auth_info;
        
        authentication_type(uint8_t protocol = 0, uint8_t algorithm = 0,
          uint8_t rdm = 0, uint64_t replay_detection = 0,
          const auth_info_type& auth_info = auth_info_type())
        : protocol(protocol), algorithm(algorithm), rdm(rdm),
        replay_detection(replay_detection), auth_info(auth_info) {}

        static authentication_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the Status Code option.
     */
    struct status_code_type {
        uint16_t code;
        std::string message;
        
        status_code_type(uint16_t code = 0, const std::string& message = "")
        : code(code), message(message) { }

        static status_code_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the Vendor-specific Information option.
     */
    struct vendor_info_type {
        typedef std::vector<uint8_t> data_type;
        
        uint32_t enterprise_number;
        data_type data;
        
        vendor_info_type(uint32_t enterprise_number = 0, 
          const data_type& data = data_type())
        : enterprise_number(enterprise_number), data(data) { }

        static vendor_info_type from_option(const option& opt);
    };
    
    
    /**
     * The type used to store the User Class option's user class data.
     */
    typedef std::vector<uint8_t> class_option_data_type;
    
    /**
     * The type used to store the User Class option.
     */
    //typedef std::vector<class_option_data_type> user_class_type;
    struct user_class_type {
        typedef std::vector<class_option_data_type> data_type;
        data_type data;

        user_class_type(const data_type& data = data_type())
        : data(data) { }

        static user_class_type from_option(const option& opt);
    };
    
    /**
     * The type used to store the Vendor Class option.
     */
    struct vendor_class_type {
        typedef std::vector<class_option_data_type> class_data_type;
        
        uint32_t enterprise_number;
        class_data_type vendor_class_data;
        
        vendor_class_type(uint32_t enterprise_number = 0, 
          const class_data_type& vendor_class_data = class_data_type())
        : enterprise_number(enterprise_number), 
        vendor_class_data(vendor_class_data) { }

        static vendor_class_type from_option(const option& opt);
    };
    
    /**
     * The type used to represent DUIDs Based on Link-layer Address Plus
     * Time. 
     */
    struct duid_llt {
        static const uint16_t duid_id = 1;
        typedef std::vector<uint8_t> lladdress_type;
        
        uint16_t hw_type;
        uint32_t time;
        lladdress_type lladdress;
        
        duid_llt(uint16_t hw_type = 0, uint32_t time = 0,
          const lladdress_type& lladdress = lladdress_type())
        : hw_type(hw_type), time(time), lladdress(lladdress) {}
        
        PDU::serialization_type serialize() const;
        
        static duid_llt from_bytes(const uint8_t* buffer, uint32_t total_sz);
    };
    
    /**
     * The type used to represent DUIDs Based on Enterprise Number
     */
    struct duid_en {
        static const uint16_t duid_id = 2;
        typedef std::vector<uint8_t> identifier_type;
        
        uint32_t enterprise_number;
        identifier_type identifier;
        
        duid_en(uint32_t enterprise_number = 0,
          const identifier_type& identifier = identifier_type())
        : enterprise_number(enterprise_number), identifier(identifier) {}
        
        PDU::serialization_type serialize() const;
        
        static duid_en from_bytes(const uint8_t* buffer, uint32_t total_sz);
    };
    
    /**
     * The type used to represent DUIDs Based on Link-layer Address.
     */
    struct duid_ll {
        static const uint16_t duid_id = 3;
        typedef std::vector<uint8_t> lladdress_type;
        
        uint16_t hw_type;
        lladdress_type lladdress;
        
        duid_ll(uint16_t hw_type = 0, 
          const lladdress_type& lladdress = lladdress_type())
        : hw_type(hw_type), lladdress(lladdress) {}
        
        PDU::serialization_type serialize() const;
        
        static duid_ll from_bytes(const uint8_t* buffer, uint32_t total_sz);
    };
    
    /**
     * Type type used to represent DUIDs. This will be stored as the 
     * value for the Client/Server Identifier options.
     */
    struct duid_type {
        typedef PDU::serialization_type data_type;
        
        uint16_t id;
        data_type data;
        
        duid_type(uint16_t id = 0, const data_type& data = data_type())
        : id(id), data(data) {}
        
        duid_type(const duid_llt& identifier)
        : id(duid_llt::duid_id), data(identifier.serialize()) {}
        
        duid_type(const duid_en& identifier)
        : id(duid_en::duid_id), data(identifier.serialize()) {}
        
        duid_type(const duid_ll& identifier)
        : id(duid_en::duid_id), data(identifier.serialize()) {}

        static duid_type from_option(const option& opt);
    };
        
    /**
     * The type used to store the Option Request option.
     */
    typedef std::vector<uint16_t> option_request_type;
    
    /**
     * The type used to store the Relay Message option.
     */
    typedef std::vector<uint8_t> relay_msg_type;
    
    /**
     * The type used to store the Interface-ID option.
     */
    typedef std::vector<uint8_t> interface_id_type;

    /**
     * \brief Extracts metadata for this protocol based on the buffer provided
     *
     * \param buffer Pointer to a buffer
     * \param total_sz Size of the buffer pointed by buffer
     */
    static metadata extract_metadata(const uint8_t *buffer, uint32_t total_sz);

    /**
     * Default constructor.
     */
    DHCPv6();
    
    /**
     * \brief Constructs a DHCPv6 object from a buffer.
     * 
     * If there is not enough size for the DHCPv6 header, or any
     * of the TLV options contains an invalid size field, a 
     * malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    DHCPv6(const uint8_t* buffer, uint32_t total_sz);

    // Getters
    
    /**
     * \brief Getter for the message type field.
     *
     * \return The stored message type field.
     */
    MessageType msg_type() const { 
        return static_cast<MessageType>(header_data_[0]); 
    }
    
    /**
     * \brief Getter for the hop count field.
     *
     * \return The stored hop count field.
     */
    uint8_t hop_count() const {
        return header_data_[1];
    }
    
    /**
     * \brief Getter for the transaction id field.
     *
     * \return The stored transaction id field.
     */
    small_uint<24> transaction_id() const { 
        return (header_data_[1] << 16) | (header_data_[2] << 8) | header_data_[3];
    }

    /**
     * \brief Getter for the peer address field.
     *
     * \return The stored peer address field.
     */
    const ipaddress_type& peer_address() const {
        return peer_addr_;
    }
    
    /**
     * \brief Getter for the link address field.
     *
     * \return The stored link address field.
     */
    const ipaddress_type& link_address() const {
        return link_addr_;
    }
    
    /**
     * \brief Getter for the DHCPv6 options.
     *
     * \return The stored options.
     */
    const options_type& options() const {
        return options_;
    }

    // Setters
    /**
     * \brief Setter for the message type field.
     *
     * \param type The new message type.
     */
    void msg_type(MessageType type);
    
    /**
     * \brief Setter for the hop count field.
     *
     * \param count The new hop count.
     */
    void hop_count(uint8_t count);
    
    /**
     * \brief Setter for the transaction id field.
     *
     * \param id The new transaction id.
     */
    void transaction_id(small_uint<24> id);
    
    /**
     * \brief Setter for the peer address field.
     *
     * \param count The new peer address.
     */
    void peer_address(const ipaddress_type& addr);
    
    /**
     * \brief Setter for the link address field.
     *
     * \param count The new link address.
     */
    void link_address(const ipaddress_type& addr);
    
    // Option getters
    
    /**
     * \brief Getter for the Identity Association for Non-Temporary
     * Addresses option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    ia_na_type ia_na() const;
    
    /**
     * \brief Getter for the Identity Association for Temporary
     * Addresses option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    ia_ta_type ia_ta() const;
    
    /**
     * \brief Getter for the Identity Association Address option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    ia_address_type ia_address() const;
    
    /**
     * \brief Getter for the Option Request option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    option_request_type option_request() const;
    
    /**
     * \brief Getter for the Preference option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    uint8_t preference() const;
    
    /**
     * \brief Getter for the Elapsed Time option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    uint16_t elapsed_time() const;
    
    /**
     * \brief Getter for the Relay Message option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    relay_msg_type relay_message() const;
    
    /**
     * \brief Getter for the Authentication option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    authentication_type authentication() const;
    
    /**
     * \brief Getter for the Server Unicast option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    ipaddress_type server_unicast() const;
    
    /**
     * \brief Getter for the Server Unicast option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    status_code_type status_code() const;
    
    /**
     * \brief Getter for the Rapid Commit option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    bool has_rapid_commit() const;
    
    /**
     * \brief Getter for the User Class option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    user_class_type user_class() const;
    
    /**
     * \brief Getter for the Vendor Class option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    vendor_class_type vendor_class() const;
    
    /**
     * \brief Getter for the Vendor-specific Information option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    vendor_info_type vendor_info() const;
    
    /**
     * \brief Getter for the Interface ID option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    interface_id_type interface_id() const;

    /**
     * \brief Getter for the Reconfigure Message option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    uint8_t reconfigure_msg() const;
    
    /**
     * \brief Getter for the Reconfigure Accept option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    bool has_reconfigure_accept() const;
    
    /**
     * \brief Getter for the Client Identifier option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    duid_type client_id() const;
    
    /**
     * \brief Getter for the Server Identifier option.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    duid_type server_id() const;
    
    // Option setters
    
    /**
     * \brief Setter for the Identity Association for Non-Temporary
     * Addresses option.
     * 
     * \param value The new IA_NA option data.
     */
    void ia_na(const ia_na_type& value);
    
    /**
     * \brief Setter for the Identity Association for Temporary
     * Addresses option.
     * 
     * \param value The new IA_TA option data.
     */
    void ia_ta(const ia_ta_type& value);
    
    /**
     * \brief Setter for the Identity Association Address option.
     * 
     * \param value The new IA Address option data.
     */
    void ia_address(const ia_address_type& value);
    
    /**
     * \brief Setter for the Identity Association Address option.
     * 
     * \param value The new Option Request option data.
     */
    void option_request(const option_request_type& value);
    
    /**
     * \brief Setter for the Preference option.
     * 
     * \param value The new Preference option data.
     */
    void preference(uint8_t value);
    
    /**
     * \brief Setter for the Elapsed Time option.
     * 
     * \param value The new Elapsed Time option data.
     */
    void elapsed_time(uint16_t value);
    
    /**
     * \brief Setter for the Relay Message option.
     * 
     * \param value The new Relay Message option data.
     */
    void relay_message(const relay_msg_type& value);
    
    /**
     * \brief Setter for the Authentication option.
     * 
     * \param value The new Authentication option data.
     */
    void authentication(const authentication_type& value);
    
    /**
     * \brief Setter for the Server Unicast option.
     * 
     * \param value The new Server Unicast option data.
     */
    void server_unicast(const ipaddress_type& value);
    
    /**
     * \brief Setter for the Status Code option.
     * 
     * \param value The new Status Code option data.
     */
    void status_code(const status_code_type& value);
    
    /**
     * \brief Adds a Rapid Commit option.
     */
    void rapid_commit();
    
    /**
     * \brief Setter for the User Class option.
     * 
     * \param value The new User Class option data.
     */
    void user_class(const user_class_type& value);
    
    /**
     * \brief Setter for the Vendor Class option.
     * 
     * \param value The new Vendor Class option data.
     */
    void vendor_class(const vendor_class_type& value);
    
    /**
     * \brief Setter for the Vendor-specific Information option.
     * 
     * \param value The new Vendor-specific Information option data.
     */
    void vendor_info(const vendor_info_type& value);
    
    /**
     * \brief Setter for the Interface ID option.
     * 
     * \param value The new Interface ID option data.
     */
    void interface_id(const interface_id_type& value);
    
    /**
     * \brief Setter for the Reconfigure Message option.
     * 
     * \param value The new Reconfigure Message option data.
     */
    void reconfigure_msg(uint8_t value);
    
    /**
     * \brief Adds a Reconfigure Accept option.
     */
    void reconfigure_accept();
    
    /**
     * \brief Setter for the Client Identifier option.
     * 
     * \param value The new Client Identifier option data.
     */
    void client_id(const duid_type& value);
    
    /**
     * \brief Setter for the Server Identifier option.
     * 
     * \param value The new Server Identifier option data.
     */
    void server_id(const duid_type& value);
    
    // Other stuff
    
    /**
     * Indicates whether this is a relay agent/server message
     */
    bool is_relay_message() const;
    
    /**
     * \brief Adds a DHCPv6 option.
     * 
     * The option is added after the last option in the option 
     * fields.
     * 
     * \param opt The option to be added
     */
    void add_option(const option& opt);
    
    /**
     * \brief Removes a DHCPv6 option.
     * 
     * If there are multiple options of the given type, only the first one
     * will be removed.
     *
     * \param type The type of the option to be removed.
     * \return true if the option was removed, false otherwise.
     */
    bool remove_option(OptionTypes type);

    /**
     * \brief Searchs for an option that matchs the given type.
     * 
     * If the option is not found, a null pointer is returned. 
     * Deleting the returned pointer will result in <b>undefined 
     * behaviour</b>.
     * 
     * \param type The option identifier to be searched.
     */
    const option* search_option(OptionTypes type) const;

    // PDU stuff
    
    /**
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. \sa PDU::header_size
     */
    uint32_t header_size() const;
    
        /** 
     * \brief Check whether ptr points to a valid response for this PDU.
     *
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const;
    
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
    DHCPv6* clone() const {
        return new DHCPv6(*this);
    }
private:
    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU *);
    void write_option(const option& option, Memory::OutputMemoryStream& stream) const;
    options_type::const_iterator search_option_iterator(OptionTypes type) const;
    options_type::iterator search_option_iterator(OptionTypes type);
    
    template <template <typename> class Functor>
    const option* safe_search_option(OptionTypes opt, uint32_t size) const {
        const option* option = search_option(opt);
        if (!option || Functor<uint32_t>()(option->data_size(), size)) {
            throw option_not_found();
        }
        return option;
    }

    template<typename T>
    T search_and_convert(OptionTypes opt) const {
        const option* option = search_option(opt);
        if (!option) {
            throw option_not_found();
        }
        return option->to<T>();
    }

    uint8_t header_data_[4];
    uint32_t options_size_;
    ipaddress_type link_addr_, peer_addr_;
    options_type options_;
};   

namespace Internals {

template<typename InputIterator>
void class_option_data2option(InputIterator start,
                              InputIterator end, 
                              std::vector<uint8_t>& buffer,
                              size_t start_index = 0) {
    size_t index = start_index;
    uint16_t uint16_t_buffer;
    while (start != end) {
        buffer.resize(buffer.size() + sizeof(uint16_t) + start->size());
        uint16_t_buffer = Endian::host_to_be(static_cast<uint16_t>(start->size()));
        std::memcpy(&buffer[index], &uint16_t_buffer, sizeof(uint16_t));
        index += sizeof(uint16_t);
        std::copy(start->begin(), start->end(), buffer.begin() + index);
        index += start->size();
        
        start++;
    }
}

template<typename OutputType>
OutputType option2class_option_data(const uint8_t* ptr, uint32_t total_sz) {
    typedef typename OutputType::value_type value_type;
    OutputType output;
    size_t index = 0;
    while (index + 2 < total_sz) {
        uint16_t size;
        std::memcpy(&size, ptr + index, sizeof(uint16_t));
        size = Endian::be_to_host(size);
        index += sizeof(uint16_t);
        if (index + size > total_sz) {
            throw option_not_found();
        }
        output.push_back(
            value_type(ptr + index, ptr + index + size)
        );
        index += size;
    }
    if (index != total_sz) {
        throw malformed_option();
    }
    return output;
}

} // Internals 
} // Tins

#endif // TINS_DHCPV6_H
