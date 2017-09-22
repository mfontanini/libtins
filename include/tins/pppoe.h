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

#ifndef TINS_PPPoE_H
#define TINS_PPPoE_H

#include <string>
#include <vector>
#include <tins/pdu.h>
#include <tins/macros.h>
#include <tins/endianness.h>
#include <tins/small_uint.h>
#include <tins/pdu_option.h>
#include <tins/cxxstd.h>

namespace Tins {
/**
 * \class PPPoE
 * \brief Represents a Point-to-point protocol over Ethernet PDU.
 */
class TINS_API PPPoE : public PDU {
public:
    /**
     * The tag types enum.
     */
    enum TagTypes {
        END_OF_LIST = 0,
        SERVICE_NAME = 0x101,
        #if TINS_IS_LITTLE_ENDIAN
            AC_NAME = 0x201,
            HOST_UNIQ = 0x301,
            AC_COOKIE = 0x401,
            VENDOR_SPECIFIC = 0x501,
            RELAY_SESSION_ID = 0x101,
            SERVICE_NAME_ERROR = 0x102,
            AC_SYSTEM_ERROR = 0x202,
            GENERIC_ERROR = 0x302
        #else
            AC_NAME = 0x102,
            HOST_UNIQ = 0x103,
            AC_COOKIE = 0x104,
            VENDOR_SPECIFIC = 0x105,
            RELAY_SESSION_ID = 0x110,
            SERVICE_NAME_ERROR = 0x201,
            AC_SYSTEM_ERROR = 0x202,
            GENERIC_ERROR = 0x203
        #endif        
    };

    /**
     * The type used to store a TLV option.
     */
    typedef PDUOption<TagTypes, PPPoE> tag;
    
    /**
     * The type used to store the options.
     */
    typedef std::vector<tag> tags_type;
    
    /**
     * The type used to store the Vendor-Specific tag's value.
     */
    struct vendor_spec_type {
        typedef std::vector<uint8_t> data_type;
        
        uint32_t vendor_id;
        data_type data;
        
        vendor_spec_type(uint32_t vendor_id = 0, const data_type& data = data_type())
        : vendor_id(vendor_id), data(data) { }
        
        static vendor_spec_type from_option(const tag& opt);
    };
    
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::PPPOE;

    /**
     * \brief Default constructor.
     * 
     * This sets the version and type fields to 0x1.
     */
    PPPoE();
    
    /**
     * \brief Constructor which creates an PPPoE object from a buffer.
     * 
     * If there is not enough size for a PPPoE header, a malformed_packet
     * exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    PPPoE(const uint8_t* buffer, uint32_t total_sz);

    // Getters

    /**
     *  \brief Getter for the version field.
     *  \return The stored version field value.
     */
    small_uint<4> version() const {
        return header_.version;
    }

    /**
     *  \brief Getter for the type field.
     *  \return The stored type field value.
     */
    small_uint<4> type() const {
        return header_.type;
    }

    /**
     *  \brief Getter for the code field.
     *  \return The stored code field value.
     */
    uint8_t code() const {
        return header_.code;
    }

    /**
     *  \brief Getter for the session_id field.
     *  \return The stored session_id field value.
     */
    uint16_t session_id() const {
        return Endian::be_to_host(header_.session_id);
    }

    /**
     *  \brief Getter for the payload_length field.
     *  \return The stored payload_length field value.
     */
    uint16_t payload_length() const {
        return Endian::be_to_host(header_.payload_length);
    }
    
    /**
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Returns the list of tags.
     */
    const tags_type& tags() const {
        return tags_;
    }

    /**
     * \sa PDU::clone
     */
    PPPoE* clone() const {
        return new PPPoE(*this);
    }
    
    const tag* search_tag(TagTypes identifier) const;
    
    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    // Setters

    /**
     *  \brief Setter for the version field.
     *  \param new_version The new version field value.
     */
    void version(small_uint<4> new_version);

    /**
     *  \brief Setter for the type field.
     *  \param new_type The new type field value.
     */
    void type(small_uint<4> new_type);

    /**
     *  \brief Setter for the code field.
     *  \param new_code The new code field value.
     */
    void code(uint8_t new_code);

    /**
     *  \brief Setter for the session_id field.
     *  \param new_session_id The new session_id field value.
     */
    void session_id(uint16_t new_session_id);

    /**
     *  \brief Setter for the payload_length field.
     *  \param new_payload_length The new payload_length field value.
     */
    void payload_length(uint16_t new_payload_length);
    
    /**
     * \brief Adds a PPPoE tag.
     *
     * \param option The option to be added.
     */
    void add_tag(const tag& option);
    
    #if TINS_IS_CXX11
        /**
         * \brief Adds a PPPoE tag.
         *
         * This move-constructs the option.
         * 
         * \param option The option to be added.
         */
        void add_tag(tag &&option) {
            tags_size_ += static_cast<uint16_t>(option.data_size() + sizeof(uint16_t) * 2);
            tags_.push_back(std::move(option));
        }
    #endif
    
    // Option setters
    
    /**
     * \brief Adds an end-of-list tag.
     */
    void end_of_list();
    
    /**
     * \brief Adds a service-name tag.
     * 
     * \param value The service name.
     */
    void service_name(const std::string& value);
    
    /**
     * \brief Adds a AC-name tag.
     * 
     * \param value The AC name.
     */
    void ac_name(const std::string& value);
    
    /**
     * \brief Adds a host-uniq tag.
     * 
     * \param value The tag's value.
     */
    void host_uniq(const byte_array& value);
    
    /**
     * \brief Adds a AC-Cookie tag.
     * 
     * \param value The tag's value.
     */
    void ac_cookie(const byte_array& value);
    
    /**
     * \brief Adds a Vendor-Specific tag.
     * 
     * \param value The tag's value.
     */
    void vendor_specific(const vendor_spec_type& value);
    
    /**
     * \brief Adds a Relay-Session-Id tag.
     * 
     * \param value The tag's value.
     */
    void relay_session_id(const byte_array& value);
    
    /**
     * \brief Adds a Service-Name-Error tag.
     * 
     * \param value The tag's value.
     */
    void service_name_error(const std::string& value);
    
    /**
     * \brief Adds a AC-System-Error tag.
     * 
     * \param value The tag's value.
     */
    void ac_system_error(const std::string& value);
    
    /**
     * \brief Adds a Generic-Error tag.
     * 
     * \param value The tag's value.
     */
    void generic_error(const std::string& value);
    
    // Option getters
    
    /**
     * \brief Getter for the service-name tag.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    std::string service_name() const;
    
    /**
     * \brief Getter for the AC-name tag.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    std::string ac_name() const;
    
    /**
     * \brief Getter for the host-uniq tag.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    byte_array host_uniq() const;

    /**
     * \brief Getter for the AC-Cookie tag.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    byte_array ac_cookie() const;
    
    /**
     * \brief Getter for the Vendor-Specific tag.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    vendor_spec_type vendor_specific() const;
    
    /**
     * \brief Getter for the Vendor-Specific tag.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    byte_array relay_session_id() const;
    
    /**
     * \brief Getter for the Service-Name-Error tag.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    std::string service_name_error() const;
    
    /**
     * \brief Getter for the AC-System-Error tag.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    std::string ac_system_error() const;
    
    /**
     * \brief Getter for the Generic-Error tag.
     * 
     * This method will throw an option_not_found exception if the
     * option is not found.
     */
    std::string generic_error() const;
private:
    void write_serialization(uint8_t* buffer, uint32_t total_sz);
    
    template<typename T>
    void add_tag_iterable(TagTypes id, const T& data) {
        add_tag(
            tag(
                id,
                data.begin(),
                data.end()
            )
        );
    }
    
    template<typename T>
    T search_and_convert(TagTypes id) const {
        const tag* t = search_tag(id);
        if (!t) {
            throw option_not_found();
        }
        return t->to<T>();
    }

    TINS_BEGIN_PACK
    struct pppoe_header {
        #if TINS_IS_LITTLE_ENDIAN
            uint8_t version:4,  
                    type:4;
            uint8_t code;
        #else
            uint16_t version:4,
                    type:4,
                    code:8;
        #endif
        uint16_t session_id;
        uint16_t payload_length;
    } TINS_END_PACK;

    pppoe_header header_;
    tags_type tags_;
    uint16_t tags_size_;
};
}

#endif // TINS_PPPoE_H
