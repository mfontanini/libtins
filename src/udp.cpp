#ifndef WIN32
    #include <netinet/in.h>
#endif
#include <cassert>
#include <cstring>
#include "utils.h"
#include "udp.h"
#include "ip.h"

Tins::UDP::UDP(uint16_t sport, uint16_t dport) : PDU(IPPROTO_UDP), _payload(0), _payload_size(0) {
    _udp.sport = sport;
    _udp.dport = dport;
    _udp.check = 0;
    _udp.len = 0;
}

void Tins::UDP::payload(uint8_t *new_payload, uint32_t new_payload_size) {
    _payload = new_payload;
    _payload_size = new_payload_size;
    _udp.len = Utils::net_to_host_s(sizeof(udphdr) + _payload_size);
}

void Tins::UDP::dport(uint16_t new_dport) {
    _udp.dport = new_dport;
}
         
void Tins::UDP::sport(uint16_t new_sport) {
    _udp.sport = new_sport;
}

uint32_t Tins::UDP::header_size() const {
    /* Round? */
    return sizeof(udphdr) + _payload_size;
}

void Tins::UDP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(udphdr) + _payload_size);
    const IP *ip_packet = dynamic_cast<const IP*>(parent);
    if(!_udp.check && ip_packet) {
        uint32_t checksum = PDU::pseudoheader_checksum(ip_packet->source_address(), ip_packet->dest_address(), header_size(), IPPROTO_UDP) + 
                            PDU::do_checksum(_payload, _payload + _payload_size) + PDU::do_checksum((uint8_t*)&_udp, ((uint8_t*)&_udp) + sizeof(udphdr));
        while (checksum >> 16)
            checksum = (checksum & 0xffff)+(checksum >> 16);
        _udp.check = Utils::net_to_host_s(~checksum);
    }
    std::memcpy(buffer, &_udp, sizeof(udphdr));
    std::memcpy(buffer + sizeof(udphdr), _payload, _payload_size);
}

