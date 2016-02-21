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

#ifndef TINS_EAPOL_H
#define TINS_EAPOL_H

#include <stdint.h>
#include "pdu.h"
#include "macros.h"
#include "small_uint.h"
#include "endianness.h"

namespace Tins {
namespace Memory {

class OutputMemoryStream;

} // Memory

/** \cond 
 * Forward declaration. Avoid header inclusion.
 */
class RSNInformation;
/** \endcond */

/**
 * \class EAPOL
 * \brief Represents the EAP encapsulation over LAN.
 */
class TINS_API EAPOL : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::EAPOL;

    /**
     * The EAPOL type enum.
     */
    enum EAPOLTYPE {
        RC4 = 1,
        RSN,
        EAPOL_WPA = 254
    };
    
    /**
     * \brief Extracts metadata for this protocol based on the buffer provided
     *
     * \param buffer Pointer to a buffer
     * \param total_sz Size of the buffer pointed by buffer
     */
    static metadata extract_metadata(const uint8_t *buffer, uint32_t total_sz);
    
    /**
     * \brief Static method to instantiate the correct EAPOL subclass 
     * based on a raw buffer.
     * 
     * If no valid EAPOL type is detected, a null pointer is returned.
     * 
     * \sa RC4EAPOL
     * \sa RSNEAPOL
     * 
     * \param buffer The buffer from which the data will be taken.
     * \param total_sz The total size of the buffer.
     */
    static EAPOL* from_bytes(const uint8_t* buffer, uint32_t total_sz);
    
    /* Getters */
    
    /**
     * \brief Getter for the version field.
     * \return The version field.
     */
    uint8_t version() const {
        return header_.version;
    }
    
    /**
     * \brief Getter for the packet type field.
     * \return The packet type field.
     */
    uint8_t packet_type() const {
        return header_.packet_type;
    }
    
    /**
     * \brief Getter for the length field.
     * \return The length field.
     */
    uint16_t length() const {
        return Endian::be_to_host(header_.length);
    }
    
    /**
     * \brief Getter for the type field.
     * \return The type field.
     */
    uint8_t type() const {
        return header_.type;
    }
    
    /* Setters */
    
    /**
     * \brief Sets the version field.
     * \param value The new version to be set.
     */
    void version(uint8_t value);
    
    /**
     * \brief Sets the packet type field.
     * \param value The new packet type to be set.
     */
    void packet_type(uint8_t value);
    
    /**
     * \brief Sets the length field.
     * \param value The new length to be set.
     */
    void length(uint16_t value);
    
    /**
     * \brief Sets the type field.
     * \param value The new type to be set.
     */
    void type(uint8_t value);
    
    /**
     * \brief Getter for the PDU's type.
     * \return Returns the PDUType corresponding to the PDU.
     */
    PDUType pdu_type() const { return PDU::EAPOL; }
protected:
    /**
     * \brief Protected constructor that sets the packet_type and type fields.
     */
    EAPOL(uint8_t packet_type, EAPOLTYPE type);
    
    /**
     * \brief Constructor which creates an EAPOL object from a buffer.
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    EAPOL(const uint8_t* buffer, uint32_t total_sz);
    
    TINS_BEGIN_PACK
    struct eapol_header {
        uint8_t version, packet_type;
        uint16_t length;
        uint8_t type;
    } TINS_END_PACK;
    
    /**
     * \brief Virtual method which should serialize the subclass specific
     * body and save it in a byte array.
     * 
     * \param buffer The pointer in which to save the serialization.
     * \param total_sz The total size of the buffer.
     */
    virtual void write_body(Memory::OutputMemoryStream& stream) = 0;
private:
    /** 
     * \brief Serialices this EAPOL PDU.
     * \param buffer The buffer in which the PDU will be serialized.
     * \param total_sz The size available in the buffer.
     * \param parent The PDU that's one level below this one on the stack.
     */
    void write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent);

    eapol_header header_;
};



/**
 * \brief Class that represents the RC4 EAPOL PDU.
 */
class TINS_API RC4EAPOL : public EAPOL {
public:
    /**
     * The type used to store the key.
     */
    typedef std::vector<uint8_t> key_type;

    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::RC4EAPOL;
    
    /**
     * The length of the key IV field
     */
    static const size_t key_iv_size = 16;
    
    /**
     * The length of the key sign field
     */
    static const size_t key_sign_size = 16;

    /**
     * \brief Default constructor.
     */
    RC4EAPOL();
    
    /**
     * \brief Constructs a RC4EAPOL object from a buffer.
     * 
     * If there is not enough size for a RC4EAPOL header in the 
     * buffer, a malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    RC4EAPOL(const uint8_t* buffer, uint32_t total_sz);
    
    /* Getters */
    
    /**
     * \brief Getter for the key length field.
     * \return The key length field.
     */
    uint16_t key_length() const {
        return Endian::be_to_host(header_.key_length);
    }
    
    /**
     * \brief Getter for the replay counter field.
     * \return The replay counter field.
     */
    uint64_t replay_counter() const {
        return Endian::be_to_host(header_.replay_counter);
    }
    
    /**
     * \brief Getter for the key IV field.
     * \return The key IV field.
     */
    const uint8_t* key_iv() const {
        return header_.key_iv;
    }
    
    /**
     * \brief Getter for the key flag field.
     * \return The key flag field.
     */
    small_uint<1> key_flag() const {
        return header_.key_flag;
    }
    
    /**
     * \brief Getter for the key index field.
     * \return The key index field.
     */
    small_uint<7> key_index() const {
        return header_.key_index;
    }
    
    /**
     * \brief Getter for the key signature field.
     * \return The key signature field.
     */
    const uint8_t* key_sign() const {
        return header_.key_sign;
    }
    
    /**
     * \brief Getter for the key field.
     * \return The key field.
     */
    const key_type& key() const {
        return key_;
    }
    
    /* Setters */
    
    /**
     * \brief Sets the key length field.
     * \param value The new key length to be set.
     */
    void key_length(uint16_t value);
    
    /**
     * \brief Sets the replay counter field.
     * \param value The new replay counter to be set.
     */
    void replay_counter(uint64_t value);
    
    /**
     * \brief Sets the key IV field.
     * \param value The new key IV to be set.
     */
    void key_iv(const uint8_t* value);
    
    /**
     * \brief Sets the key flag field.
     * \param value The new key flag to be set.
     */
    void key_flag(small_uint<1> value);
    
    /**
     * \brief Sets the key index field.
     * \param value The new key index to be set.
     */
    void key_index(small_uint<7> value);
    
    /**
     * \brief Sets the key signature field.
     * \param value The new key signature to be set.
     */
    void key_sign(const uint8_t* value);
    
    /**
     * \brief Sets the key field.
     * \param value The new key to be set.
     */
    void key(const key_type& value);
    
    /* Virtual method override. */
    
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
     * \brief Getter for the PDU's type.
     * \return Returns the PDUType corresponding to the PDU.
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
       return flag == pdu_flag || EAPOL::matches_flag(flag);
    }
    
    /**
     * \brief Clones this PDU.
     * 
     * \sa PDU::clone
     */
    RC4EAPOL* clone() const {
        return new RC4EAPOL(*this);
    }
private:
    TINS_BEGIN_PACK
    struct rc4_eapol_header {
        uint16_t key_length;
        uint64_t replay_counter;
        uint8_t key_iv[key_iv_size];
        uint8_t key_index:7,
                key_flag:1;
        uint8_t key_sign[16];
    } TINS_END_PACK;
    
    void write_body(Memory::OutputMemoryStream& stream);
    
    
    key_type key_;
    rc4_eapol_header header_;
};


/**
 * \brief Class that represents the RSN EAPOL PDU.
 */
class TINS_API RSNEAPOL : public EAPOL {
public:
    /**
     * The type used to store the key.
     */
    typedef std::vector<uint8_t> key_type;

    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::RSNEAPOL;
    
    /**
     * The length of the key IV field
     */
    static const size_t key_iv_size = 16;
    
    /**
     * The length of the nonce field
     */
    static const size_t nonce_size = 32;

    /**
     * The length of the mic field
     */
    static const size_t mic_size = 16;
    
    /**
     * The length of the rsc field
     */
    static const size_t rsc_size = 8;
    
    /**
     * The length of the id field
     */
    static const size_t id_size = 8;
    
    /**
     * \brief Creates an instance of RSNEAPOL.
     */
    RSNEAPOL();
    
    /**
     * \brief Constructs a RSNEAPOL object from a buffer.
     * 
     * If there is not enough size for the RSNEAPOL header, a
     * malformed_packet exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    RSNEAPOL(const uint8_t* buffer, uint32_t total_sz);
    
    /* Getters */
    
    /**
     * \brief Getter for the key length field.
     * \return The key length field.
     */
    uint16_t key_length() const {
        return Endian::be_to_host(header_.key_length);
    }
    
    /**
     * \brief Getter for the replay counter field.
     * \return The replay counter field.
     */
    uint64_t replay_counter() const {
        return Endian::be_to_host(header_.replay_counter);
    }
    
    /**
     * \brief Getter for the key IV field.
     * \return The key IV field.
     */
    const uint8_t* key_iv() const {
        return header_.key_iv;
    }
    
    /**
     * \brief Getter for the nonce field.
     * \return The nonce field.
     */
    const uint8_t* nonce() const {
        return header_.nonce;
    }
    
    /**
     * \brief Getter for the rsc field.
     * \return The rsc field.
     */
    const uint8_t* rsc() const {
        return header_.rsc;
    }
    
    /**
     * \brief Getter for the id field.
     * \return The id field.
     */
    const uint8_t* id() const {
        return header_.id;
    }
    
    /**
     * \brief Getter for the mic field.
     * \return The mic field.
     */
    const uint8_t* mic() const {
        return header_.mic;
    }
    
    /**
     * \brief Getter for the wpa length field.
     * \return The wpa length field.
     */
    uint16_t wpa_length() const {
        return Endian::be_to_host(header_.wpa_length);
    }
    
    /**
     * \brief Getter for the key field.
     * \return The key field.
     */
    const key_type& key() const {
        return key_;
    }
    
    /**
     * \brief Getter for the key mic field.
     * \return 1 if this EAPOL PDU contains a valid MIC, 0 otherwise.
     */
    small_uint<1> key_mic() const {
        return header_.key_mic;
    }

    /**
     * \brief Getter for the secure field.
     * \return The secure field.
     */
    small_uint<1> secure() const {
        return header_.secure;
    }

    /**
     * \brief Getter for the error field.
     * \return The error field.
     */
    small_uint<1> error() const {
        return header_.error;
    }

    /**
     * \brief Getter for the request field.
     * \return The request field.
     */
    small_uint<1> request() const {
        return header_.request;
    }

    /**
     * \brief Getter for the encrypted field.
     * \return The encrypted field.
     */
    small_uint<1> encrypted() const {
        return header_.encrypted;
    }

    /**
     * \brief Getter for the key descriptor field.
     * \return The key descriptor field.
     */
    small_uint<3> key_descriptor() const {
        return header_.key_descriptor;
    }

    /**
     * \brief Getter for the key type field.
     * 
     * \return 1 if this is a pairwise key, 0 otherwise.
     */
    small_uint<1> key_t() const {
        return header_.key_t;
    }

    /**
     * \brief Getter for the key_index field.
     * \return The key_index field.
     */
    small_uint<2> key_index() const {
        return header_.key_index;
    }

    /**
     * \brief Getter for the install field.
     * \return The install field.
     */
    small_uint<1> install() const {
        return header_.install;
    }

    /**
     * \brief Getter for the key_ack field.
     * \return The key_ack field.
     */
    small_uint<1> key_ack() const {
        return header_.key_ack;
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
    
    /* Setters */
    
    /**
     * \brief Sets the key length field.
     * \param value The new key length to be set.
     */
    void key_length(uint16_t value);
    
    /**
     * \brief Sets the replay counter field.
     * \param value The new replay counter to be set.
     */
    void replay_counter(uint64_t value);
    
    /**
     * \brief Sets the key IV field.
     *
     * The input pointer has to contain at least key_iv_size bytes. The IV
     * will be copied into this PDU.
     *
     * \param ptr The new key IV to be set.
     */
    void key_iv(const uint8_t* ptr);
    
    /**
     * \brief Sets the nonce field.
     * 
     * The pointer has to contain at least nonce_size bytes. The pointer's contents
     * will be copied.
     *
     * \param ptr The new nonce to be set.
     */
    void nonce(const uint8_t* ptr);
    
    /**
     * \brief Sets the rsc field.
     *
     * The pointer has to contain at least rsc_size bytes. The pointer's contents
     * will be copied.
     *
     * \param ptr The new rsc to be set.
     */
    void rsc(const uint8_t* ptr);
    
    /**
     * \brief Sets the id field.
     *
     * The pointer has to contain at least id_size bytes. The pointer's contents
     * will be copied.
     *
     * \param ptr The new id to be set.
     */
    void id(const uint8_t* ptr);
    
    /**
     * \brief Sets the mic field.
     * 
     * The pointer has to contain at least mic_size bytes. The pointer's contents
     * will be copied.
     *
     * \param ptr The new mic to be set.
     */
    void mic(const uint8_t* ptr);
    
    /**
     * \brief Sets the wpa length field.
     * \param length The new wpa length to be set.
     */
    void wpa_length(uint16_t length);
    
    /**
     * \brief Sets the key field.
     * \param value The new key to be set.
     */
    void key(const key_type& value);
    
    /**
     * \brief Setter for the key_mic field.
     * \param value The new to be set.
     */
    void key_mic(small_uint<1> value);

    /**
     * \brief Setter for the secure field.
     * \param value The new to be set.
     */
    void secure(small_uint<1> value);

    /**
     * \brief Setter for the error field.
     * \param flag The new to be set.
     */
    void error(small_uint<1> flag);

    /**
     * \brief Setter for the request field.
     * \param flag The new to be set.
     */
    void request(small_uint<1> flag);

    /**
     * \brief Setter for the encrypted field.
     * \param flag The new to be set.
     */
    void encrypted(small_uint<1 > flag);

    /**
     * \brief Setter for the key_descriptor field.
     * \param value The new to be set.
     */
    void key_descriptor(small_uint<3> value);

    /**
     * \brief Setter for the key_t field.
     * \param flag The new to be set.
     */
    void key_t(small_uint<1> flag);

    /**
     * \brief Setter for the key_index field.
     * \param value The new to be set.
     */
    void key_index(small_uint<2> value);

    /**
     * \brief Setter for the install field.
     * \param flag The new to be set.
     */
    void install(small_uint<1> flag);

    /**
     * \brief Setter for the key_ack field.
     * \param flag The new to be set.
     */
    void key_ack(small_uint<1> flag);
    
    /**
     * \brief Getter for the PDU's type.
     * \return Returns the PDUType corresponding to the PDU.
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
       return flag == pdu_flag || EAPOL::matches_flag(flag);
    }
    
    /**
     * \brief Clones this PDU.
     * 
     * \sa PDU::clone
     */
    RSNEAPOL* clone() const {
        return new RSNEAPOL(*this);
    }
private:
    TINS_BEGIN_PACK
    struct rsn_eapol_header {
    #if TINS_IS_LITTLE_ENDIAN
        uint16_t key_mic:1,
            secure:1,
            error:1,
            request:1,
            encrypted:1,
            reserved:3, 
            key_descriptor:3,
            key_t:1,
            key_index:2,
            install:1,
            key_ack:1;       
        uint16_t key_length;
        uint64_t replay_counter;
        uint8_t nonce[nonce_size], key_iv[key_iv_size];
        uint8_t rsc[rsc_size], id[id_size];
        uint8_t mic[mic_size];
        uint16_t wpa_length;
    #else
        uint16_t reserved:3,
            encrypted:1,
            request:1,
            error:1,
            secure:1,
            key_mic:1,
            key_ack:1,
            install:1,
            key_index:2,
            key_t:1,
            key_descriptor:3;
        uint16_t key_length;
        uint64_t replay_counter;
        uint8_t nonce[nonce_size], key_iv[key_iv_size];
        uint8_t rsc[rsc_size], id[id_size];
        uint8_t mic[mic_size];
        uint16_t wpa_length;
    #endif
    } TINS_END_PACK;
    
    void write_body(Memory::OutputMemoryStream& stream);
    
    
    rsn_eapol_header header_;
    key_type key_;
};

} // Tins

#endif // TINS_EAPOL_H
