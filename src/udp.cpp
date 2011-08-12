#ifndef WIN32
    #include <netinet/in.h>
#endif
#include "udp.h"

Tins::UDP::UDP(uint16_t sport, uint16_t dport) : PDU(IPPROTO_UDP), _payload(0) {
    _udp.sport = sport;
    _udp.dport = dport;
}

void Tins::UDP::payload(uint8_t *new_payload, uint32_t new_payload_size) {
    _payload = new_payload;
    _udp.len = sizeof(udphdr) + new_payload_size;
}
