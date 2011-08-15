#include <cstring>
#include <cassert>
#include <netinet/in.h>
#include "arp.h"
#include "utils.h"


using namespace std;

Tins::ARP::ARP() : PDU(0x0608) {
    std::memset(&_arp, 0, sizeof(arphdr));
    _arp.ar_hrd = 0x0100;
    _arp.ar_pro = 0x0008;
    _arp.ar_hln = 6;
    _arp.ar_pln = 4;
}

void Tins::ARP::set_arp_request(const string &ip_dst, const string &ip_src, const string &hw_src) {
    _arp.ar_tip = Utils::resolve_ip(ip_dst);
    _arp.ar_sip = Utils::resolve_ip(ip_src);
}

uint32_t Tins::ARP::header_size() const {
    return sizeof(arphdr);
}

void Tins::ARP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    assert(total_sz >= sizeof(arphdr));
    memcpy(buffer, &_arp, sizeof(arphdr));
}

