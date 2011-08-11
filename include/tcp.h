#ifndef __TCP_H
#define __TCP_H


#include <stdint.h>
#ifndef WIN32
    #include <endian.h>
#endif
#include "pdu.h"

namespace Tins {

    class TCP : public PDU {
    public:
        enum Flags {
            FIN,
            SYN,
            RST,
            PSH,
            ACK,
            URG,
            ECE,
            CWR
        };
    
        TCP(uint16_t dport = 0, uint16_t sport = 0);
        
        inline uint16_t dport() const { return _tcp.dport; }
        inline uint16_t sport() const { return _tcp.sport; }
        inline uint32_t seq() const { return _tcp.seq; }
        inline uint32_t ack_seq() const { return _tcp.ack_seq; }
        inline uint16_t window() const { return _tcp.window; }
        inline uint16_t check() const { return _tcp.check; }
        inline uint16_t urg_ptr() const { return _tcp.urg_ptr; }
        
        void dport(uint16_t new_dport);
        void sport(uint16_t new_sport);
        void seq(uint32_t new_seq);
        void ack_seq(uint32_t new_ack_seq);
        void window(uint16_t new_window);
        void check(uint16_t new_check);
        void urg_ptr(uint16_t new_urg_ptr);
        
        void set_flag(Flags tcp_flag, uint8_t value);
        
        uint16_t do_checksum() const;
        
        /* Virtual methods */
        uint32_t header_size() const;
        void write_serialization(uint8_t *buffer, uint32_t total_sz);
    private:
        struct tcphdr {
            uint16_t sport;
            uint16_t dport;
            uint32_t seq;
            uint32_t ack_seq;
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint16_t res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
        #elif __BYTE_ORDER == __BIG_ENDIAN
            uint16_t doff:4,
                res1:4,
                cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
        #else
        #error	"Endian is not LE nor BE..."
        #endif	
            uint16_t	window;
            uint16_t	check;
            uint16_t	urg_ptr;
        } __attribute__((packed));
        
        static const uint16_t DEFAULT_WINDOW;
        
        tcphdr _tcp;
    };
};

#endif
