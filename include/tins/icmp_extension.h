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

#ifndef TINS_ICMP_EXTENSION_H
#define TINS_ICMP_EXTENSION_H

#include <vector>
#include <list>
#include <stdint.h>
#include "macros.h"
#include "small_uint.h"
#include "endianness.h"

namespace Tins {

class MPLS;

/**
 * \brief Class that represents an ICMP extension object
 */
class TINS_API ICMPExtension {
public:
    /**
     * The type used to store the payload 
     */
    typedef std::vector<uint8_t> payload_type;

    /**
     * The type that will be returned when serializing an extensions 
     * structure object
     */
    typedef std::vector<uint8_t> serialization_type;

    /**
     * \brief Default constructor
     */
    ICMPExtension();

    /**
     * \brief Constructor taking class and type
     *
     * \param ext_class The extension class
     * \param ext_type The extension sub-type
     */
    ICMPExtension(uint8_t ext_class, uint8_t ext_type);

    /**
     * \brief Constructs an ICMP extension from a buffer
     *
     * \param buffer The input buffer
     * \param total_sz The input buffer size
     */
    ICMPExtension(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Setter for the extension class field
     *
     * \param value The new extension class field value
     */
    void extension_class(uint8_t value);

    /**
     * \brief Setter for the extension sub-type field
     *
     * \param value The new extension sub-type field value
     */
    void extension_type(uint8_t value);

    /**
     * \brief Setter for the payload field
     *
     * \param value The new payload field value
     */
    void payload(const payload_type& value);

    /**
     * \brief Getter for the extension class field
     *
     * \return The extension class field value
     */
    uint8_t extension_class() const {
        return extension_class_;
    }

    /**
     * \brief Getter for the extension sub-type field
     *
     * \return The extension sub-type field value
     */
    uint8_t extension_type() const {
        return extension_type_;
    }

    /**
     * \brief Getter for the extension payload field
     *
     * \return The extension payload field value
     */
    const payload_type& payload() const {
        return payload_;
    }

    /**
     * \brief Gets the size of this ICMP extension
     *
     * This returns the basic header size + the payload size
     *
     * \return The size of this extension
     */
    uint32_t size() const;

    /**
     * \brief Serializes this extension into a buffer
     *
     * \param buffer The output buffer in which to store the serialization
     * \param buffer_size The size of the output buffer
     */
    void serialize(uint8_t* buffer, uint32_t buffer_size) const;

    /**
     * \brief Serializes this extension object
     * 
     * \return The serialized extension
     */
    serialization_type serialize() const;
private:
    static const uint32_t BASE_HEADER_SIZE;

    payload_type payload_;
    uint8_t extension_class_, extension_type_;
};

/**
 * \brief Class that represents an ICMP extensions structure
 */
class TINS_API ICMPExtensionsStructure {
public:
    /**
     * The minimum ICMP payload size that has to be present when the PDU
     * contains extensions.
     */
    static const uint32_t MINIMUM_ICMP_PAYLOAD;

    /**
     * The type that will be returned when serializing an extensions 
     * structure object
     */
    typedef ICMPExtension::serialization_type serialization_type;

    /**
     * The type used to store the list of ICMP extensions in this structure
     */
    typedef std::list<ICMPExtension> extensions_type;

    /**
     * \brief Default constructor
     *
     * This sets the version to 2, as specified in RFC 4884
     */
    ICMPExtensionsStructure();

    /**
     * \brief Constructor from a buffer.
     *
     * This constructor will find, parse and store the extension
     * stack in the buffer.
     */
    ICMPExtensionsStructure(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Setter for the version field
     *
     * \param value The new version field value
     */
    void version(small_uint<4> value);

    /**
     * \brief Setter for the reserved field
     *
     * \param value The new reserved field value
     */
    void reserved(small_uint<12> value);

    /**
     * \brief Getter for the version field
     *
     * \return The version field value
     */
    small_uint<4> version() const {
        uint16_t value = Endian::be_to_host(version_and_reserved_);
        return (value >> 12) & 0xf;
    }

    /**
     * \brief Getter for the reserved field
     *
     * \return The reserved field value
     */
    small_uint<12> reserved() const {
        uint16_t value = Endian::be_to_host(version_and_reserved_);
        return value & 0xfff;
    }

    /**
     * \brief Getter for the checksum field
     *
     * \return The checksum field value
     */
    uint16_t checksum() const {
        return Endian::be_to_host(checksum_);
    }

    /**
     * \brief Getter for the extensions stored by this structure
     *
     * \return The extensions stored in this structure
     */
    const extensions_type& extensions() const {
        return extensions_;
    }

    /**
     * \brief Adds an extension to this structure
     *
     * \param extension The extension to be added
     */
    void add_extension(const ICMPExtension& extension);

    /**
     * \brief Adds an MPLS extension to this structure
     *
     * This will construct an extension using the provided MPLS packet as
     * its payload. The class and type fields will be set appropriately.
     *
     * \param extension The MPLS payload to be used for the new extension
     */
    void add_extension(MPLS& mpls);

    /**
     * \brief Gets the size of this ICMP extensions structure
     *
     * \return The size of this structure
     */
    uint32_t size() const;

    /**
     * \brief Serializes this extension structure into a buffer
     *
     * \param buffer The output buffer in which to store the serialization
     * \param buffer_size The size of the output buffer
     */
    void serialize(uint8_t* buffer, uint32_t buffer_size);

    /**
     * \brief Serializes this extension structure
     * 
     * \return The serialized extension structure
     */
    serialization_type serialize();

    /**
     * \brief Validates if the given input contains a valid extension structure
     *
     * The validation is performed by calculating the checksum of the input
     * and comparing to the checksum value in the input buffer.
     *
     * \param buffer The input buffer
     * \param total_sz The size of the input buffer
     * \return true iff the buffer contains a valid ICMP extensions structure
     */
    static bool validate_extensions(const uint8_t* buffer, uint32_t total_sz);
private:
    static const uint32_t BASE_HEADER_SIZE;

    uint16_t version_and_reserved_;
    uint16_t checksum_;
    extensions_type extensions_;
};

} // Tins

#endif // TINS_ICMP_EXTENSION_H
