#ifndef __ARP_H
#define __ARP_H


#include <string>
#include "pdu.h"

namespace Tins {
    
    class ARP : public PDU {
    public:
        enum Flags {
            REQUEST = 0x0100,
            REPLY   = 0x0200
        };
    
        ARP();
        
        void set_arp_request(const std::string &ip_dst, const std::string &ip_src, const std::string &hw_src = "");
        
        uint32_t header_size() const;
        
        bool send(PacketSender* sender);
    private:
        struct arphdr {
            uint16_t ar_hrd;	/* format of hardware address	*/
            uint16_t ar_pro;	/* format of protocol address	*/
            uint8_t	ar_hln;		/* length of hardware address	*/
            uint8_t	ar_pln;		/* length of protocol address	*/
            uint16_t ar_op;		/* ARP opcode (command)		*/
            
            uint8_t ar_sha[6];	/* sender hardware address	*/
            uint32_t ar_sip;	/* sender IP address		*/
            uint8_t ar_tha[6];	/* target hardware address	*/
            uint32_t ar_tip;	/* target IP address		*/
        } __attribute__((packed));
        
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        arphdr _arp;
    };
};
#endif
