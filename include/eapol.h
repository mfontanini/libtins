/*
 * Copyright (c) 2014, Matias Fontanini
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
    
    /** \cond 
     * Forward declaration. Avoid header inclusion.
     */
    class RSNInformation;
    /** \endcond */
    
    /**
     * \class EAPOL
     * \brief Represents the EAP encapsulation over LAN.
     */
    class EAPOL : public PDU {
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
        static EAPOL *from_bytes(const uint8_t *buffer, uint32_t total_sz);
        
        /* Getters */
        
        /**
         * \brief Getter for the version field.
         * \return The version field.
         */
        uint8_t version() const { return _header.version; }
        
        /**
         * \brief Getter for the packet type field.
         * \return The packet type field.
         */
        uint8_t packet_type() const { return _header.packet_type; }
        
        /**
         * \brief Getter for the length field.
         * \return The length field.
         */
        uint16_t length() const { return Endian::be_to_host(_header.length); }
        
        /**
         * \brief Getter for the type field.
         * \return The type field.
         */
        uint8_t type() const { return _header.type; }
        
        /* Setters */
        
        /**
         * \brief Sets the version field.
         * \param new_version The new version to be set.
         */
        void version(uint8_t new_version);
        
        /**
         * \brief Sets the packet type field.
         * \param new_ptype The new packet type to be set.
         */
        void packet_type(uint8_t new_ptype);
        
        /**
         * \brief Sets the length field.
         * \param new_length The new length to be set.
         */
        void length(uint16_t new_length);
        
        /**
         * \brief Sets the type field.
         * \param new_type The new type to be set.
         */
        void type(uint8_t new_type);
        
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
        EAPOL(const uint8_t *buffer, uint32_t total_sz);
        
        TINS_BEGIN_PACK
        struct eapolhdr {
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
        virtual void write_body(uint8_t *buffer, uint32_t total_sz) = 0;
    private:
        /** 
         * \brief Serialices this EAPOL PDU.
         * \param buffer The buffer in which the PDU will be serialized.
         * \param total_sz The size available in the buffer.
         * \param parent The PDU that's one level below this one on the stack.
         */
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
    
        eapolhdr _header;
    };
    
    
    
    /**
     * \brief Class that represents the RC4 EAPOL PDU.
     */
    class RC4EAPOL : public EAPOL {
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
        RC4EAPOL(const uint8_t *buffer, uint32_t total_sz);
        
        /* Getters */
        
        /**
         * \brief Getter for the key length field.
         * \return The key length field.
         */
        uint16_t key_length() const { return Endian::be_to_host(_header.key_length); }
        
        /**
         * \brief Getter for the replay counter field.
         * \return The replay counter field.
         */
        uint64_t replay_counter() const { return Endian::be_to_host(_header.replay_counter); }
        
        /**
         * \brief Getter for the key IV field.
         * \return The key IV field.
         */
        const uint8_t *key_iv() const { return _header.key_iv; }
        
        /**
         * \brief Getter for the key flag field.
         * \return The key flag field.
         */
        small_uint<1> key_flag() const { return _header.key_flag; }
        
        /**
         * \brief Getter for the key index field.
         * \return The key index field.
         */
        small_uint<7> key_index() const { return _header.key_index; }
        
        /**
         * \brief Getter for the key signature field.
         * \return The key signature field.
         */
        const uint8_t *key_sign() const { return _header.key_sign; }
        
        /**
         * \brief Getter for the key field.
         * \return The key field.
         */
        const key_type &key() const { return _key; }
        
        /* Setters */
        
        /**
         * \brief Sets the key length field.
         * \param new_key_length The new key length to be set.
         */
        void key_length(uint16_t new_key_length);
        
        /**
         * \brief Sets the replay counter field.
         * \param new_replay_counter The new replay counter to be set.
         */
        void replay_counter(uint64_t new_replay_counter);
        
        /**
         * \brief Sets the key IV field.
         * \param new_key_iv The new key IV to be set.
         */
        void key_iv(const uint8_t *new_key_iv);
        
        /**
         * \brief Sets the key flag field.
         * \param new_key_flag The new key flag to be set.
         */
        void key_flag(small_uint<1> new_key_flag);
        
        /**
         * \brief Sets the key index field.
         * \param new_key_index The new key index to be set.
         */
        void key_index(small_uint<7> new_key_index);
        
        /**
         * \brief Sets the key signature field.
         * \param new_key_sign The new key signature to be set.
         */
        void key_sign(const uint8_t *new_key_sign);
        
        /**
         * \brief Sets the key field.
         * \param new_key The new key to be set.
         */
        void key(const key_type &new_key);
        
        /* Virtual method override. */
        
        /**
         * \brief Returns the header size.
         *
         * This metod overrides PDU::header_size. This size includes the
         * payload and options size.
         *
         * \sa PDU::header_size
         */
        uint32_t header_size() const;
        
        /**
         * \brief Getter for the PDU's type.
         * \return Returns the PDUType corresponding to the PDU.
         */
        PDUType pdu_type() const { return PDU::RC4EAPOL; }
        
        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == PDU::RC4EAPOL || EAPOL::matches_flag(flag);
        }
        
        /**
         * \brief Clones this PDU.
         * 
         * \sa PDU::clone
         */
        RC4EAPOL *clone() const {
            return new RC4EAPOL(*this);
        }
    private:
        TINS_BEGIN_PACK
        struct rc4hdr {
            uint16_t key_length;
            uint64_t replay_counter;
            uint8_t key_iv[key_iv_size];
            uint8_t key_index:7,
                    key_flag:1;
            uint8_t key_sign[16];
        } TINS_END_PACK;
        
        void write_body(uint8_t *buffer, uint32_t total_sz);
        
        
        key_type _key;
        rc4hdr _header;
    };
    
    
    /**
     * \brief Class that represents the RSN EAPOL PDU.
     */
    class RSNEAPOL : public EAPOL {
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
        RSNEAPOL(const uint8_t *buffer, uint32_t total_sz);
        
        /* Getters */
        
        /**
         * \brief Getter for the key length field.
         * \return The key length field.
         */
        uint16_t key_length() const { return Endian::be_to_host(_header.key_length); }
        
        /**
         * \brief Getter for the replay counter field.
         * \return The replay counter field.
         */
        uint64_t replay_counter() const { return Endian::be_to_host(_header.replay_counter); }
        
        /**
         * \brief Getter for the key IV field.
         * \return The key IV field.
         */
        const uint8_t *key_iv() const { return _header.key_iv; }
        
        /**
         * \brief Getter for the nonce field.
         * \return The nonce field.
         */
        const uint8_t *nonce() const { return _header.nonce; }
        
        /**
         * \brief Getter for the rsc field.
         * \return The rsc field.
         */
        const uint8_t *rsc() const { return _header.rsc; }
        
        /**
         * \brief Getter for the id field.
         * \return The id field.
         */
        const uint8_t *id() const { return _header.id; }
        
        /**
         * \brief Getter for the mic field.
         * \return The mic field.
         */
        const uint8_t *mic() const { return _header.mic; }
        
        /**
         * \brief Getter for the wpa length field.
         * \return The wpa length field.
         */
        uint16_t wpa_length() const { return Endian::be_to_host(_header.wpa_length); }
        
        /**
         * \brief Getter for the key field.
         * \return The key field.
         */
        const key_type &key() const { return _key; }
        
        /**
         * \brief Getter for the key mic field.
         * \return 1 if this EAPOL PDU contains a valid MIC, 0 otherwise.
         */
        small_uint<1> key_mic() const { return _header.key_mic; };

        /**
         * \brief Getter for the secure field.
         * \return The secure field.
         */
        small_uint<1> secure() const { return _header.secure; };

        /**
         * \brief Getter for the error field.
         * \return The error field.
         */
        small_uint<1> error() const { return _header.error; };

        /**
         * \brief Getter for the request field.
         * \return The request field.
         */
        small_uint<1> request() const { return _header.request; };

        /**
         * \brief Getter for the encrypted field.
         * \return The encrypted field.
         */
        small_uint<1> encrypted() const { return _header.encrypted; };

        /**
         * \brief Getter for the key descriptor field.
         * \return The key descriptor field.
         */
        small_uint<3> key_descriptor() const { return _header.key_descriptor; };

        /**
         * \brief Getter for the key type field.
         * 
         * \return 1 if this is a pairwise key, 0 otherwise.
         */
        small_uint<1> key_t() const { return _header.key_t; };

        /**
         * \brief Getter for the key_index field.
         * \return The key_index field.
         */
        small_uint<2> key_index() const { return _header.key_index; };

        /**
         * \brief Getter for the install field.
         * \return The install field.
         */
        small_uint<1> install() const { return _header.install; };

        /**
         * \brief Getter for the key_ack field.
         * \return The key_ack field.
         */
        small_uint<1> key_ack() const { return _header.key_ack; };
        
        /**
         * \brief Returns the header size.
         *
         * This metod overrides PDU::header_size. This size includes the
         * payload and options size.
         *
         * \sa PDU::header_size
         */
        uint32_t header_size() const;
        
        /* Setters */
        
        /**
         * \brief Sets the key length field.
         * \param new_key_length The new key length to be set.
         */
        void key_length(uint16_t new_key_length);
        
        /**
         * \brief Sets the replay counter field.
         * \param new_replay_counter The new replay counter to be set.
         */
        void replay_counter(uint64_t new_replay_counter);
        
        /**
         * \brief Sets the key IV field.
         * \param new_key_iv The new key IV to be set.
         */
        void key_iv(const uint8_t *new_key_iv);
        
        /**
         * \brief Sets the nonce field.
         * 
         * This method sets the nonce field. This field is 32 bytes long,
         * therefore the input buffer should be at least that length.
         * \param new_nonce The new nonce to be set.
         */
        void nonce(const uint8_t *new_nonce);
        
        /**
         * \brief Sets the rsc field.
         * \param new_rsc The new rsc to be set.
         */
        void rsc(const uint8_t *new_rsc);
        
        /**
         * \brief Sets the id field.
         * \param new_id The new id to be set.
         */
        void id(const uint8_t *new_id);
        
        /**
         * \brief Sets the mic field.
         * 
         * This method sets the mic field. This field is 16 bytes long,
         * therefore the input buffer should be at least that length.
         * \param new_mic The new mic to be set.
         */
        void mic(const uint8_t *new_mic);
        
        /**
         * \brief Sets the wpa length field.
         * \param new_wpa_length The new wpa length to be set.
         */
        void wpa_length(uint16_t new_wpa_length);
        
        /**
         * \brief Sets the key field.
         * \param new_key The new key to be set.
         */
        void key(const key_type &new_key);
        
        /**
         * \brief Setter for the key_mic field.
         * \param new_key_mic The new to be set.
         */
        void key_mic(small_uint<1> new_key_mic);

        /**
         * \brief Setter for the secure field.
         * \param new_secure The new to be set.
         */
        void secure(small_uint<1> new_secure);

        /**
         * \brief Setter for the error field.
         * \param new_error The new to be set.
         */
        void error(small_uint<1> new_error);

        /**
         * \brief Setter for the request field.
         * \param new_request The new to be set.
         */
        void request(small_uint<1> new_request);

        /**
         * \brief Setter for the encrypted field.
         * \param new_encrypted The new to be set.
         */
        void encrypted(small_uint<1 > new_encrypted);

        /**
         * \brief Setter for the key_descriptor field.
         * \param new_key_descriptor The new to be set.
         */
        void key_descriptor(small_uint<3> new_key_descriptor);

        /**
         * \brief Setter for the key_t field.
         * \param new_key_t The new to be set.
         */
        void key_t(small_uint<1> new_key_t);

        /**
         * \brief Setter for the key_index field.
         * \param new_key_index The new to be set.
         */
        void key_index(small_uint<2> new_key_index);

        /**
         * \brief Setter for the install field.
         * \param new_install The new to be set.
         */
        void install(small_uint<1> new_install);

        /**
         * \brief Setter for the key_ack field.
         * \param new_key_ack The new to be set.
         */
        void key_ack(small_uint<1> new_key_ack);
        
        /**
         * \brief Getter for the PDU's type.
         * \return Returns the PDUType corresponding to the PDU.
         */
        PDUType pdu_type() const { return PDU::RSNEAPOL; }
        
        /**
         * \brief Check wether this PDU matches the specified flag.
         * \param flag The flag to match
         * \sa PDU::matches_flag
         */
        bool matches_flag(PDUType flag) const {
           return flag == PDU::RSNEAPOL || EAPOL::matches_flag(flag);
        }
        
        /**
         * \brief Clones this PDU.
         * 
         * \sa PDU::clone
         */
        RSNEAPOL *clone() const {
            return new RSNEAPOL(*this);
        }
    private:
        TINS_BEGIN_PACK
        struct rsnhdr {
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
        
        void write_body(uint8_t *buffer, uint32_t total_sz);
        
        
        rsnhdr _header;
        key_type _key;
    };
}

#endif // TINS_EAPOL_H
