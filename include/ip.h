#ifndef __IP_H
#define __IP_H

#ifndef WIN32
    #include <endian.h>
#endif
#include <string>
#include <stdint.h>
#include "pdu.h"

namespace Tins {

    class IP : public PDU {
    public:
        IP(const std::string &ip_dst = "", const std::string &ip_src = "");
        IP(uint32_t ip_dst = 0, uint32_t ip_src = 0);

        inline uint8_t tos() const { return _ip.tos; }
        inline uint16_t tot_len() const { return _ip.tot_len; }
        inline uint16_t id() const { return _ip.id; }
        inline uint16_t frag_off() const { return _ip.frag_off; }
        inline uint8_t ttl() const { return _ip.ttl; }
        inline uint8_t protocol() const { return _ip.protocol; }
        inline uint16_t check() const { return _ip.check; }
        inline uint32_t source_address() const { return _ip.saddr; }
        inline uint32_t dest_address() const  { return _ip.daddr; }

        void tos(uint8_t new_tos);
        void tot_len(uint16_t new_tot_len);
        void id(uint16_t new_id);
        void frag_off(uint16_t new_frag_off);
        void ttl(uint8_t new_ttl);
        void protocol(uint8_t new_protocol);
        void check(uint16_t new_check);
        void source_address(const std::string &ip);
        void source_address(uint32_t ip);
        void dest_address(const std::string &ip);
        void dest_address(uint32_t ip);

        /* Virtual methods */
        uint32_t header_size() const;
        bool send(PacketSender* sender);
    private:
        struct iphdr {
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            unsigned int ihl:4;
            unsigned int version:4;
        #elif __BYTE_ORDER == __BIG_ENDIAN
            unsigned int version:4;
            unsigned int ihl:4;
        #else
        # error "Endian is not LE nor BE..."
        #endif
            uint8_t tos;
            uint16_t tot_len;
            uint16_t id;
            uint16_t frag_off;
            uint8_t ttl;
            uint8_t protocol;
            uint16_t check;
            uint32_t saddr;
            uint32_t daddr;
            /*The options start here. */
        } __attribute__((packed));

        void init_ip_fields();
        void write_serialization(uint8_t *buffer, uint32_t total_sz);

        iphdr _ip;
    };
};

#endif
