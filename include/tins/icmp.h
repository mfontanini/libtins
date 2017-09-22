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

#ifndef TINS_ICMP_H
#define TINS_ICMP_H

// Windows likes to define macros with not-so-common-names, which break
// this code
#ifdef _WIN32
    #ifdef TIMESTAMP_REQUEST
        #undef TIMESTAMP_REQUEST
    #endif // TIMESTAMP_REQUEST

    #ifdef TIMESTAMP_REPLY
        #undef TIMESTAMP_REPLY
    #endif // TIMESTAMP_REPLY
#endif // _WIN32

#include <tins/macros.h>
#include <tins/pdu.h>
#include <tins/endianness.h>
#include <tins/ip_address.h>
#include <tins/icmp_extension.h>

namespace Tins {
namespace Memory {

class InputMemoryStream;

} // Memory

/** 
 * \class ICMP
 * \brief Class that represents an ICMP PDU.
 *
 * ICMP is the representation of the ICMP PDU. Instances of this class
 * must be sent over a level 3 PDU, this will otherwise fail.
 */
class TINS_API ICMP : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::ICMP;

    /**
     * The type used to store addresses.
     */
    typedef IPv4Address address_type;

    /** \brief ICMP flags
     */
    enum Flags {
        ECHO_REPLY       = 0,
        DEST_UNREACHABLE = 3,
        SOURCE_QUENCH    = 4,
        REDIRECT         = 5,
        ECHO_REQUEST     = 8,
        TIME_EXCEEDED    = 11,
        PARAM_PROBLEM    = 12,
        TIMESTAMP_REQUEST = 13,
        TIMESTAMP_REPLY  = 14,
        INFO_REQUEST     = 15,
        INFO_REPLY       = 16,
        ADDRESS_MASK_REQUEST = 17,
        ADDRESS_MASK_REPLY = 18
    };

    /**
     * \brief Extracts metadata for this protocol based on the buffer provided
     *
     * \param buffer Pointer to a buffer
     * \param total_sz Size of the buffer pointed by buffer
     */
    static metadata extract_metadata(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Creates an instance of ICMP.
     *
     * If no flag is specified, then ECHO_REQUEST will be used.
     * \param flag The type flag which will be set.
     */
    ICMP(Flags flag = ECHO_REQUEST);

    /**
     * \brief Constructs an ICMP object from a buffer.
     * 
     * If there is not enough size for an ICMP header, a 
     * malformed_packet exception is thrown.
     * 
     * Any extra data in the buffer will be stored in a RawPDU.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    ICMP(const uint8_t* buffer, uint32_t total_sz);
    
    /**
     * \brief Sets the code field.
     *
     * \param new_code The code which will be stored in the ICMP struct.
     */
    void code(uint8_t new_code);

    /** \brief Sets the type field.
     *
     * \param type The type which will be stored in the ICMP struct.
     */
    void type(Flags type);

    /**
     * \brief Setter for the id field.
     *
     * \param new_id uint16_t with the new id.
     */
    void id(uint16_t new_id);

    /**
     * \brief Setter for the sequence field.
     *
     * \param new_seq uint16_t with the new sequence.
     */
    void sequence(uint16_t new_seq);

    /**
     * \brief Setter for the gateway field.
     *
     * \param new_gw The new value for the gateway field.
     */
    void gateway(address_type new_gw);

    /**
     * \brief Setter for the mtu field.
     *
     * \param new_mtu uint16_t with the new sequence.
     */
    void mtu(uint16_t new_mtu);
    
    /**
     * \brief Setter for the pointer field.
     *
     * \param new_pointer uint8_t with the new pointer.
     */
    void pointer(uint8_t new_pointer);

    /**
     * \brief Setter for the original timestamp field.
     *
     * \param new_timestamp the value to be set.
     */
    void original_timestamp(uint32_t new_timestamp);

    /**
     * \brief Setter for the receive timestamp field.
     *
     * \param new_timestamp the value to be set.
     */
    void receive_timestamp(uint32_t new_timestamp);

    /**
     * \brief Setter for the transmit timestamp field.
     *
     * \param new_timestamp the value to be set.
     */
    void transmit_timestamp(uint32_t new_timestamp);

    /**
     * \brief Setter for the address mask field.
     *
     * \param new_mask the value to be set.
     */
    void address_mask(address_type new_mask);

    /**
     * \brief Sets echo request flag for this PDU.
     *
     * \param id The identifier for this request.
     * \param seq The sequence number for this request.
     */
    void set_echo_request(uint16_t id, uint16_t seq);

    /**
     * \brief Sets echo reply flag for this PDU.
     *
     * \param id The identifier for this request.
     * \param seq The sequence number for this request.
     */
    void set_echo_reply(uint16_t id, uint16_t seq);

    /**
     * \brief Sets information request flag for this PDU.
     *
     * \param id The identifier for this request.
     * \param seq The sequence number for this request.
     */
    void set_info_request(uint16_t id, uint16_t seq);

    /**
     * \brief Sets information reply flag for this PDU.
     *
     * \param id The identifier for this request.
     * \param seq The sequence number for this request.
     */
    void set_info_reply(uint16_t id, uint16_t seq);

    /**
     * \brief Sets destination unreachable for this PDU.
     */
    void set_dest_unreachable();

    /**
     * \brief Sets time exceeded flag for this PDU.
     *
     * \param ttl_exceeded If true this PDU will represent a ICMP ttl
     * exceeded, otherwise it will represent a fragment reassembly
     * time exceeded.
     */
    void set_time_exceeded(bool ttl_exceeded = true);

    /**
     * \brief Sets parameter problem flag for this PDU.
     *
     * \param set_pointer Indicates whether a pointer to the bad octet
     * is provided.
     * \param bad_octet Identifies the octet in which the error was
     * detected. If set_pointer == false, it is ignored.
     */
    void set_param_problem(bool set_pointer = false, uint8_t bad_octet = 0);

    /**
     * \brief Sets source quench flag for this PDU.
     */
    void set_source_quench();

    /**
     * \brief Sets redirect flag for this PDU.
     *
     * \param icode The code to be set.
     * \param address Address of the gateway to which traffic should
     * be sent.
     */
    void set_redirect(uint8_t icode, address_type address);

    /**
     * \brief Getter for the ICMP type flag.
     *
     * \return The type flag for this ICMP PDU.
     */
    Flags type() const {
        return (Flags)header_.type;
    }

    /**
     * \brief Getter for the ICMP code flag.
     *
     * \return The code flag for this ICMP PDU.
     */
    uint8_t code() const {
        return header_.code;
    }

    /**
     * \brief Getter for the checksum field.
     *
     * \return Returns the checksum as an unit16_t.
     */
    uint16_t checksum() const {
        return Endian::be_to_host(header_.check);
    }

    /**
     * \brief Getter for the echo id.
     *
     * \return Returns the echo id.
     */
    uint16_t id() const {
        return Endian::be_to_host(header_.un.echo.id);
    }

    /**
     * \brief Getter for the echo sequence number.
     *
     * \return Returns the echo sequence number.
     */
    uint16_t sequence() const {
        return Endian::be_to_host(header_.un.echo.sequence);
    }

    /**
     * \brief Getter for the gateway field.
     *
     * \return Returns the gateway field value.
     */
    address_type gateway() const {
        return address_type(Endian::be_to_host(header_.un.gateway));
    }

    /**
     * \brief Getter for the pointer field.
     *
     * \return Returns the pointer field value.
     */
    uint8_t pointer() const {
        return header_.un.rfc4884.pointer;
    }

    /**
     * \brief Getter for the length field.
     *
     * \return Returns the length field value.
     */
    uint8_t length() const {
        return header_.un.rfc4884.length;
    }
    
    /**
      * \brief Getter for the mtu field.
      *
      * \return Returns the mtu field value.
      */
    uint16_t mtu() const {
        return Endian::be_to_host(header_.un.frag.mtu);
    }

    /**
      * \brief Getter for the original timestamp field.
      *
      * \return Returns the original timestamp value.
      */
    uint32_t original_timestamp() const {
        return Endian::be_to_host(orig_timestamp_or_address_mask_);
    }

    /**
      * \brief Getter for the receive timestamp field.
      *
      * \return Returns the receive timestamp value.
      */
    uint32_t receive_timestamp() const {
        return Endian::be_to_host(recv_timestamp_);
    }

    /**
      * \brief Getter for the transmit timestamp field.
      *
      * \return Returns the transmit timestamp value.
      */
    uint32_t transmit_timestamp() const {
        return Endian::be_to_host(trans_timestamp_);
    }

    /**
      * \brief Getter for the address mask field.
      *
      * \return Returns the address mask value.
      */
    address_type address_mask() const {
        return address_type(Endian::be_to_host(orig_timestamp_or_address_mask_));
    }

    /**
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. This size includes the
     * payload and options size. 
     *
     * \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Returns the trailer size.
     *
     * This method overrides PDU::trailer_size. This size will hold the extensions size
     *
     * \sa PDU::header_size
     */
    uint32_t trailer_size() const;

    /**
     * \brief Check whether ptr points to a valid response for this PDU.
     *
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const;

    /** 
     * \brief Getter for the extensions field.
     *
     * \return The extensions field
     */
    const ICMPExtensionsStructure& extensions() const {
        return extensions_;
    }

    /** 
     * \brief Getter for the extensions field.
     *
     * \return The extensions field
     */
    ICMPExtensionsStructure& extensions() {
        return extensions_;
    }

    /**
     * \brief Indicates whether this object contains ICMP extensions
     */
    bool has_extensions() const {
        return !extensions_.extensions().empty();
    }

    /**
     * \brief Sets whether the length field will be set for packets that use it
     *
     * As defined in RFC 4884, some ICMP packet types can have a length field. This
     * method controlers whether the length field is set or not.
     *
     * Note that this only indicates that the packet should use this field. The 
     * actual value will be set during the packet's serialization.
     *
     * Note that, in order to br RFC compliant, if the size of the encapsulated
     * PDU is greater than 128, the length field will always be set, regardless
     * of whether this method was called or not.
     *
     * /param value true iff the length field should be set appropriately
     */
    void use_length_field(bool value);

    /**
     * \brief Getter for the PDU's type.
     *
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \sa PDU::clone
     */
    ICMP* clone() const {
        return new ICMP(*this);
    }
private:
    TINS_BEGIN_PACK
    struct icmp_header {
        uint8_t	type;
        uint8_t	code;
        uint16_t check;
        union {
            struct {
                uint16_t id;
                uint16_t sequence;
            } echo;
            uint32_t gateway;
            struct {
                uint16_t unused;
                uint16_t mtu;
            } frag;
            struct {
                uint8_t pointer;
                uint8_t length;
                uint16_t unused;
            } rfc4884;
        } un;
    } TINS_END_PACK;

    void checksum(uint16_t new_check);    
    void write_serialization(uint8_t* buffer, uint32_t total_sz);
    uint32_t get_adjusted_inner_pdu_size() const;
    void try_parse_extensions(Memory::InputMemoryStream& stream);
    bool are_extensions_allowed() const;

    icmp_header header_;
    uint32_t orig_timestamp_or_address_mask_;
    uint32_t recv_timestamp_;
    uint32_t trans_timestamp_;
    ICMPExtensionsStructure extensions_;
};

} // Tins

#endif // TINS_ICMP_H
