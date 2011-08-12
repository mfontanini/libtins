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
        
        /** \brief Set the payload.
         * 
         * Payload is NOT copied. Therefore, pointers provided as 
         * payloads must be freed manually by the user.
         * \param new_payload New payload.
         * \param new_payload_size New payload's size
         */
        void payload(uint8_t *new_payload, uint32_t new_payload_size);
    private:
        struct udphdr {
            uint16_t sport;
            uint16_t dport;
            uint16_t len;
            uint16_t check;
        } __attribute__((packed));
        
        udphdr _udp;
        uint8_t *payload;
    };
};

#endif
