#ifndef __UDP_H
#define __UDP_H


#include "pdu.h"

namespace Tins {

    /** \brief UDP represents the UDP PDU.
     * 
     * UDP is the representation of the UDP PDU. Instances of this class
     * must be sent over a level 3 PDU, this will otherwise fail.
     */
    class UDP : public PDU {
    public:
        /** \brief UDP constructor.
         * 
         * Creates an instance of UDP. Destination and source port can
         * be provided, otherwise both will be 0.
         * \param dport Destination port.
         * \param sport Source port.
         * */
        UDP(uint16_t sport = 0, uint16_t dport = 0);
        
        
        /** \brief Returns the payload.
         */
        inline const uint8_t *payload() const { return _payload; }
         
         /** \brief Returns the destination port
          */
        inline uint16_t dport() const { return _udp.dport; }
        
        /** \brief Returns the source port
          */
        inline uint16_t sport() const { return _udp.sport; }
        
        /** \brief Set the destination port.
         * 
         * \param new_dport The new destination port.
         */
        void dport(uint16_t new_dport);
         
        /** \brief Set the source port.
         * 
         * \param new_sport The new source port.
         */
        void sport(uint16_t new_sport);
         
        /** \brief Set the payload.
         * 
         * Payload is NOT copied. Therefore, pointers provided as 
         * payloads must be freed manually by the user.
         * \param new_payload New payload.
         * \param new_payload_size New payload's size
         */
        void payload(uint8_t *new_payload, uint32_t new_payload_size);
        
        /* Virtual methods */
        /** \brief Returns the header size.
         * 
         * This metod overrides PDU::header_size. This size includes the
         * payload and options size. \sa PDU::header_size
         */
        uint32_t header_size() const;
    private:
        struct udphdr {
            uint16_t sport;
            uint16_t dport;
            uint16_t len;
            uint16_t check;
        } __attribute__((packed));
        
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        udphdr _udp;
        uint8_t *_payload;
        uint32_t _payload_size;
    };
};

#endif
