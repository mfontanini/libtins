#ifndef __EAPOL_H
#define __EAPOL_H


#include "pdu.h"


namespace Tins {
    /**
     * \brief Class that represents the EAP encapsulation over LAN.
     */
    class EAPOL : public PDU {
    protected:
        /**
         * \brief Protected constructor that sets the packet_type and type fields.
         */
        EAPOL(uint8_t packet_type, uint8_t type);
        
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
        uint16_t length() const { return _header.length; }
        
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
     * 
     */
    class RC4EAPOL : public EAPOL {
    public:
        /**
         * \brief Creates an instance of RC4EAPOL
         */
        RC4EAPOL();
        
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
        uint16_t key_length() const { return _header.key_length; }
        
        /**
         * \brief Getter for the replay counter field.
         * \return The replay counter field.
         */
        uint64_t replay_counter() const { return _header.replay_counter; }
        
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
    private:
        struct rc4hdr {
            uint16_t key_length;
            uint64_t replay_counter;
            uint8_t key_iv[16];
            uint8_t key_index:7,
                    key_flag:1;
            uint8_t key_sign[16];
        } __attribute__((__packed__));
        
        void write_body(uint8_t *buffer, uint32_t total_sz);
        
        
        uint8_t *_key;
        uint32_t _key_size;
        rc4hdr _header;
    };
};

#endif
