#include <cstring>
#include <cassert>
#ifndef WIN32
    #include <netinet/in.h>
#endif
#include "tcp.h"
#include "utils.h"


const uint16_t Tins::TCP::DEFAULT_WINDOW = 32678;

Tins::TCP::TCP(uint16_t dport, uint16_t sport) : PDU(IPPROTO_TCP) {
    std::memset(&_tcp, 0, sizeof(tcphdr));
    _tcp.dport = Utils::net_to_host_s(dport);
    _tcp.sport = Utils::net_to_host_s(sport);
    _tcp.doff = sizeof(tcphdr) / sizeof(uint32_t);
    _tcp.window = Utils::net_to_host_s(DEFAULT_WINDOW);
}

void Tins::TCP::dport(uint16_t new_dport) {
    _tcp.dport = Utils::net_to_host_s(new_dport);
}

void Tins::TCP::sport(uint16_t new_sport) {
    _tcp.sport = Utils::net_to_host_s(new_sport);
}

void Tins::TCP::seq(uint32_t new_seq) {
    _tcp.seq = new_seq;
}

void Tins::TCP::ack_seq(uint32_t new_ack_seq) {
    _tcp.ack_seq = new_ack_seq;
}

void Tins::TCP::window(uint16_t new_window) {
    _tcp.window = new_window;
}

void Tins::TCP::check(uint16_t new_check) {
    _tcp.check = new_check;
}

void Tins::TCP::urg_ptr(uint16_t new_urg_ptr) {
    _tcp.urg_ptr = new_urg_ptr;
}

void Tins::TCP::set_flag(Flags tcp_flag, uint8_t value) {
    switch(tcp_flag) {
        case FIN:
            _tcp.fin = value;
            break;
        case SYN:
            _tcp.syn = value;
            break;
        case RST:
            _tcp.rst = value;
            break;
        case PSH:
            _tcp.psh = value;
            break;
        case ACK:
            _tcp.ack = value;
            break;
        case URG:
            _tcp.urg = value;
            break;
        case ECE:
            _tcp.ece = value;
            break;
        case CWR:
            _tcp.cwr = value;
            break;
    };
}

uint16_t Tins::TCP::do_checksum() const {
    const uint8_t *ptr = (const uint8_t*)&_tcp, *end = (const uint8_t*)&_tcp + sizeof(tcphdr);
    uint16_t checksum(0);
    while(ptr < end)
        checksum += *(ptr++);
    return checksum;
}

uint32_t Tins::TCP::header_size() const {
    return sizeof(tcphdr);
}

void Tins::TCP::write_serialization(uint8_t *buffer, uint32_t total_sz) {
    assert(total_sz >= sizeof(tcphdr));
    _tcp.check = Utils::net_to_host_s(do_checksum());
    memcpy(buffer, &_tcp, sizeof(tcphdr));
}
