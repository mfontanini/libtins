#ifndef WIN32
    #include <netinet/in.h>
#endif
#include <cstring>
#include <cassert>
#include "icmp.h"
#include "utils.h"


uint16_t Tins::ICMP::global_id = 0, Tins::ICMP::global_seq = 0;


Tins::ICMP::ICMP(Flags flag) : PDU(IPPROTO_ICMP) {
    std::memset(&_icmp, 0, sizeof(icmphdr));
    switch(flag) {
        case ECHO_REPLY:
            break;
        case ECHO_REQUEST:
            set_echo_request();
            break;
        case DEST_UNREACHABLE:
            set_dest_unreachable();
            break;
        default:
            break;
    };
}

void Tins::ICMP::code(uint8_t new_code) {
    _icmp.code = new_code;
}

void Tins::ICMP::type(uint8_t new_type) {
    _icmp.type = new_type;
}

uint32_t Tins::ICMP::header_size() const {
    return sizeof(icmphdr);
}

void Tins::ICMP::set_echo_request(uint16_t id, uint16_t seq) {
    _icmp.type = ECHO_REQUEST;
    _icmp.un.echo.id = Utils::net_to_host_s(id);
    _icmp.un.echo.sequence = Utils::net_to_host_s(seq);
}

void Tins::ICMP::set_echo_request() {
    set_echo_request(global_id++, global_seq++);
    if(global_id == 0xffff)
        global_id = 0;
    if(global_seq == 0xffff)
        global_seq = 0;
}

void Tins::ICMP::set_echo_reply(uint16_t id, uint16_t seq) {
    _icmp.type = ECHO_REPLY;
    _icmp.un.echo.id = Utils::net_to_host_s(id);
    _icmp.un.echo.sequence = Utils::net_to_host_s(seq);
}

void Tins::ICMP::set_echo_reply() {
    set_echo_reply(global_id++, global_seq++);
    if(global_id == 0xffff)
        global_id = 0;
    if(global_seq == 0xffff)
        global_seq = 0;
}

void Tins::ICMP::set_info_request(uint16_t id, uint16_t seq) {
    _icmp.type = INFO_REQUEST;
    _icmp.code = 0;
    _icmp.un.echo.id = Utils::net_to_host_s(id);
    _icmp.un.echo.sequence = Utils::net_to_host_s(seq);
}

void Tins::ICMP::set_info_reply(uint16_t id, uint16_t seq) {
    _icmp.type = INFO_REPLY;
    _icmp.code = 0;
    _icmp.un.echo.id = Utils::net_to_host_s(id);
    _icmp.un.echo.sequence = Utils::net_to_host_s(seq);
}

void Tins::ICMP::set_dest_unreachable() {
    _icmp.type = DEST_UNREACHABLE;
}

void Tins::ICMP::set_time_exceeded(bool ttl_exceeded) {
    _icmp.type = TIME_EXCEEDED;
    _icmp.code = (ttl_exceeded) ? 0 : 1;
}

void Tins::ICMP::set_param_problem(bool set_pointer, uint8_t bad_octet) {
    _icmp.type = PARAM_PROBLEM;
    if(set_pointer) {
        _icmp.code = 0;
        _icmp.un.echo.id = bad_octet;
    }
    else
        _icmp.code = 1;
}

void Tins::ICMP::set_source_quench() {
    _icmp.type = SOURCE_QUENCH;
}

void Tins::ICMP::set_redirect(uint8_t icode, uint32_t address) {
    _icmp.type = REDIRECT;
    _icmp.code = icode;
    _icmp.un.gateway = address;
}

void Tins::ICMP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    assert(total_sz >= sizeof(icmphdr));
    if(!_icmp.check) {
        uint32_t checksum = PDU::do_checksum(buffer + sizeof(icmphdr), buffer + total_sz) + PDU::do_checksum((uint8_t*)&_icmp, ((uint8_t*)&_icmp) + sizeof(icmphdr));
        while (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16);
        _icmp.check = Utils::net_to_host_s(~checksum);
    }
    memcpy(buffer, &_icmp, sizeof(icmphdr));
    _icmp.check = 0;
}


