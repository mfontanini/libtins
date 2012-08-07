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

#ifndef TINS_EAPOL_H
#define TINS_EAPOL_H


#include "pdu.h"
#include "utils.h"


namespace Tins {
    
    /** \cond 
     * Forward declaration. Avoid header inclusion.
     */
    class RSNInformation;
    /** \endcond */
    
    /**
     * \brief Class that represents the EAP encapsulation over LAN.
     */
    class EAPOL : public PDU {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::EAPOL;
    
        enum EAPOLTYPE {
            RC4 = 1,
            RSN,
            EAPOL_WPA = 254
        };
        
        /**
         * \brief Static method to instantiate the correct EAPOL subclass 
         * based on a raw buffer.
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
        uint16_t length() const { return Utils::net_to_host_s(_header.length); }
        
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
        void length(uint8_t new_length);
        
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
         * \brief Copy constructor.
         */
        EAPOL(const EAPOL &other);
        
        /**
         * \brief Constructor which creates an EAPOL object from a buffer.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        EAPOL(const uint8_t *buffer, uint32_t total_sz);
        
        void copy_eapol_fields(const EAPOL *other);
        
        struct eapolhdr {
            uint8_t version, packet_type;
            uint16_t length;
            uint8_t type;
        } __attribute__((__packed__));
        
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
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::RC4EAPOL;
    
        /**
         * \brief Creates an instance of RC4EAPOL
         */
        RC4EAPOL();
        
        /**
         * \brief Constructor which creates an RC4EAPOL object from a buffer.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        RC4EAPOL(const uint8_t *buffer, uint32_t total_sz);
        
        /**
         * \brief Copy constructor.
         */
        RC4EAPOL(const RC4EAPOL &other);
        
        /**
         * \brief Copy assignment operator.
         */
        RC4EAPOL &operator= (const RC4EAPOL &other);
        
        /**
         * \brief RC4EAPOL destructor
         * 
         * Memory allocated for the key field is freed(if any).
         */
        ~RC4EAPOL();
        
        /* Getters */
        
        /**
         * \brief Getter for the key length field.
         * \return The key length field.
         */
        uint16_t key_length() const { return Utils::net_to_host_s(_header.key_length); }
        
        /**
         * \brief Getter for the replay counter field.
         * \return The replay counter field.
         */
        uint64_t replay_counter() const { return Utils::net_to_host_ll(_header.replay_counter); }
        
        /**
         * \brief Getter for the key IV field.
         * \return The key IV field.
         */
        const uint8_t *key_iv() const { return _header.key_iv; }
        
        /**
         * \brief Getter for the key flag field.
         * \return The key flag field.
         */
        uint8_t key_flag() const { return _header.key_flag; }
        
        /**
         * \brief Getter for the key index field.
         * \return The key index field.
         */
        uint8_t key_index() const { return _header.key_index; }
        
        /**
         * \brief Getter for the key signature field.
         * \return The key signature field.
         */
        const uint8_t *key_sign() const { return _header.key_sign; }
        
        /**
         * \brief Getter for the key field.
         * \return The key field.
         */
        const uint8_t *key() const { return _key; }
        
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
        void replay_counter(uint16_t new_replay_counter);
        
        /**
         * \brief Sets the key IV field.
         * \param new_key_iv The new key IV to be set.
         */
        void key_iv(const uint8_t *new_key_iv);
        
        /**
         * \brief Sets the key flag field.
         * \param new_key_flag The new key flag to be set.
         */
        void key_flag(bool new_key_flag);
        
        /**
         * \brief Sets the key index field.
         * \param new_key_index The new key index to be set.
         */
        void key_index(uint8_t new_key_index);
        
        /**
         * \brief Sets the key signature field.
         * \param new_key_sign The new key signature to be set.
         */
        void key_sign(const uint8_t *new_key_sign);
        
        /**
         * \brief Sets the key field.
         * \param new_key The new key to be set.
         */
        void key(const uint8_t *new_key, uint32_t sz);
        
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
        bool matches_flag(PDUType flag) {
           return flag == PDU::RC4EAPOL || EAPOL::matches_flag(flag);
        }
        
        /**
         * \brief Clones this PDU.
         * 
         * \sa PDU::clone_pdu
         */
        PDU *clone_pdu() const;
    private:
        struct rc4hdr {
            uint16_t key_length;
            uint64_t replay_counter;
            uint8_t key_iv[16];
            uint8_t key_index:7,
                    key_flag:1;
            uint8_t key_sign[16];
        } __attribute__((__packed__));
        
        void copy_fields(const RC4EAPOL *other);
        void write_body(uint8_t *buffer, uint32_t total_sz);
        
        
        uint8_t *_key;
        uint32_t _key_size;
        rc4hdr _header;
    };
    
    
    /**
     * \brief Class that represents the RSN EAPOL PDU.
     */
    class RSNEAPOL : public EAPOL {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::RSNEAPOL;
    
        /**
         * \brief Creates an instance of RSNEAPOL.
         */
        RSNEAPOL();
        
        /**
         * \brief Constructor which creates an RSNEAPOL object from a buffer.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        RSNEAPOL(const uint8_t *buffer, uint32_t total_sz);
        
        /**
         * \brief Copy constructor.
         */
        RSNEAPOL(const RSNEAPOL &other);
        
        /**
         * \brief Copy assignment operator.
         */
        RSNEAPOL &operator= (const RSNEAPOL &other);
        
        /**
         * \brief Destructor.
         * 
         * Memory allocated for the key field is freed(if any).
         */
        ~RSNEAPOL();
        
        /* Getters */
        
        /**
         * \brief Getter for the key length field.
         * \return The key length field.
         */
        uint16_t key_length() const { return Utils::net_to_host_s(_header.key_length); }
        
        /**
         * \brief Getter for the replay counter field.
         * \return The replay counter field.
         */
        uint64_t replay_counter() const { return Utils::net_to_host_ll(_header.replay_counter); }
        
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
        uint64_t rsc() const { return Utils::net_to_host_ll(_header.rsc); }
        
        /**
         * \brief Getter for the id field.
         * \return The id field.
         */
        uint64_t id() const { return Utils::net_to_host_ll(_header.id); }
        
        /**
         * \brief Getter for the mic field.
         * \return The mic field.
         */
        const uint8_t *mic() const { return _header.mic; }
        
        /**
         * \brief Getter for the wpa length field.
         * \return The wpa length field.
         */
        uint16_t wpa_length() const { return Utils::net_to_host_s(_header.wpa_length); }
        
        /**
         * \brief Getter for the key field.
         * \return The key field.
         */
        const uint8_t *key() const { return _key; }
        
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
        void replay_counter(uint16_t new_replay_counter);
        
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
        void rsc(uint64_t new_rsc);
        
        /**
         * \brief Sets the id field.
         * \param new_id The new id to be set.
         */
        void id(uint64_t new_id);
        
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
        void key(const uint8_t *new_key, uint32_t sz);
        
        /**
         * \brief Sets RSN information for this EAPOL PDU.
         * 
         * This method copies the RSN information and copies it in the
         * key field. Therefore, if a key has been set, this will remove it.
         * \param rsn The RSN information to be set.
         * \sa RSNInformation.
         */
        void rsn_information(const RSNInformation &rsn);
        
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
        bool matches_flag(PDUType flag) {
           return flag == PDU::RSNEAPOL || EAPOL::matches_flag(flag);
        }
        
        /**
         * \brief Clones this PDU.
         * 
         * \sa PDU::clone_pdu
         */
        PDU *clone_pdu() const;
    private:
        struct rsnhdr {
            uint16_t key_mic:1,
                secure:1,
                error:1,
                request:1,
                encrypted:1,
                reserved:3, 
                key_descriptor:3,
                key_type:1,
                key_index:2,
                install:1,
                key_ack:1;       
            uint16_t key_length;
            uint64_t replay_counter;
            uint8_t nonce[32], key_iv[16];
            uint64_t rsc, id;
            uint8_t mic[16];
            uint16_t wpa_length;
        } __attribute__((__packed__));
        
        
        void copy_fields(const RSNEAPOL *other);
        void write_body(uint8_t *buffer, uint32_t total_sz);
        
        
        rsnhdr _header;
        uint8_t *_key;
        uint32_t _key_size;
    };
};

#endif // TINS_EAPOL_H
