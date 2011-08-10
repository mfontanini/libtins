#include <cstring>
#include <cassert>
#ifndef WIN32
    #include <netinet/in.h>
#endif
#include "ip.h"
#include "utils.h"

using namespace std;


Tins::IP::IP(const string &ip_dst, const string &ip_src) : PDU(IPPROTO_IP) {
    memset(&_ip, 0, sizeof(iphdr));
    if(ip_dst.size())
        _ip.daddr = Utils::ip_to_int(ip_dst);
    if(ip_src.size())
        _ip.saddr = Utils::ip_to_int(ip_src);
}

Tins::IP::IP(uint32_t ip_dst, uint32_t ip_src) : PDU(IPPROTO_IP) {
    memset(&_ip, 0, sizeof(iphdr));
    _ip.daddr = ip_dst;
    _ip.saddr = ip_src;
}

void Tins::IP::tos(uint8_t new_tos) {
    _ip.tos = new_tos;
}

void Tins::IP::tot_len(uint16_t new_tot_len) {
    _ip.tot_len = new_tot_len;
}

void Tins::IP::id(uint16_t new_id) {
    _ip.id = new_id;
}

void Tins::IP::frag_off(uint16_t new_frag_off) {
    _ip.frag_off = new_frag_off;
}

void Tins::IP::ttl(uint8_t new_ttl) {
    _ip.ttl = new_ttl;
}

void Tins::IP::protocol(uint8_t new_protocol) {
    _ip.protocol = new_protocol;
}

void Tins::IP::check(uint16_t new_check) {
    _ip.check = new_check;
}

void Tins::IP::source_address(const string &ip) {
    _ip.saddr = Utils::ip_to_int(ip);
}

void Tins::IP::source_address(uint32_t ip) {
    _ip.saddr = ip;
}

void Tins::IP::dest_address(const string &ip) {
    _ip.daddr = Utils::ip_to_int(ip);
}

void Tins::IP::dest_address(uint32_t ip) {
    _ip.daddr = ip;
}

uint32_t Tins::IP::header_size() const {
    return sizeof(iphdr);
}

void Tins::IP::write_serialization(uint8_t *buffer, uint32_t total_sz) {
    assert(total_sz >= sizeof(iphdr));
    memcpy(buffer, &_ip, sizeof(iphdr));
}
