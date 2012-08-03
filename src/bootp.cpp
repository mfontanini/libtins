#include <stdexcept>
#include <cstring>
#include <cassert>
#include "bootp.h"


Tins::BootP::BootP() : PDU(255), _vend_size(64) {
    _vend = new uint8_t[64];
    std::memset(&_bootp, 0, sizeof(bootphdr));
    std::memset(_vend, 0, 64);
}

Tins::BootP::BootP(const uint8_t *buffer, uint32_t total_sz, uint32_t vend_field_size) : PDU(255), _vend(0), _vend_size(vend_field_size) {
    if(total_sz < sizeof(bootphdr) + vend_field_size)
        throw std::runtime_error("Not enough size for a BootP header in the buffer.");
    std::memcpy(&_bootp, buffer, sizeof(bootphdr));
    buffer += sizeof(bootphdr);
    total_sz -= sizeof(bootphdr);
    if(_vend_size) {
        _vend = new uint8_t[_vend_size];
        std::memcpy(_vend, buffer, _vend_size);
    }
    // Maybe RawPDU on what is left on the buffer?...
}

Tins::BootP::BootP(const BootP &other) : PDU(other) {
    copy_bootp_fields(&other);
}

Tins::BootP &Tins::BootP::operator= (const BootP &other) {
    copy_bootp_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

Tins::BootP::~BootP() {
    delete[] _vend;
}

uint32_t Tins::BootP::header_size() const {
    return sizeof(bootphdr) + _vend_size;
}

void Tins::BootP::opcode(uint8_t new_opcode) {
    _bootp.opcode = new_opcode;
}

void Tins::BootP::htype(uint8_t new_htype) {
    _bootp.htype = new_htype;
}

void Tins::BootP::hlen(uint8_t new_hlen) {
    _bootp.hlen = new_hlen;
}

void Tins::BootP::hops(uint8_t new_hops) {
    _bootp.hops = new_hops;
}

void Tins::BootP::xid(uint32_t new_xid) {
    _bootp.xid = Utils::net_to_host_l(new_xid);
}

void Tins::BootP::secs(uint16_t new_secs) {
    _bootp.secs = Utils::net_to_host_s(new_secs);
}

void Tins::BootP::padding(uint16_t new_padding) {
    _bootp.padding = Utils::net_to_host_s(new_padding);
}

void Tins::BootP::ciaddr(IPv4Address new_ciaddr) {
    _bootp.ciaddr = new_ciaddr;
}

void Tins::BootP::yiaddr(IPv4Address new_yiaddr) {
    _bootp.yiaddr = new_yiaddr;
}

void Tins::BootP::siaddr(IPv4Address new_siaddr) {
    _bootp.siaddr = new_siaddr;
}

void Tins::BootP::giaddr(IPv4Address new_giaddr) {
    _bootp.giaddr = new_giaddr;
}

void Tins::BootP::chaddr(const uint8_t *new_chaddr) {
    std::memcpy(_bootp.chaddr, new_chaddr, _bootp.hlen);
}

void Tins::BootP::sname(const uint8_t *new_sname) {
    std::memcpy(_bootp.sname, new_sname, sizeof(_bootp.sname));
}

void Tins::BootP::file(const uint8_t *new_file) {
    std::memcpy(_bootp.file, new_file, sizeof(_bootp.file));
}

void Tins::BootP::vend(uint8_t *new_vend, uint32_t size) {
    delete[] _vend;
    _vend_size = size;
    _vend = new uint8_t[size];
    std::memcpy(_vend, new_vend, size);
}

void Tins::BootP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(bootphdr) + _vend_size);
    std::memcpy(buffer, &_bootp, sizeof(bootphdr));
    std::memcpy(buffer + sizeof(bootphdr), _vend, _vend_size);
}

void Tins::BootP::copy_bootp_fields(const BootP *other) {
    std::memcpy(&_bootp, &other->_bootp, sizeof(_bootp));
    _vend_size = other->_vend_size;
    if(_vend_size) {
        _vend = new uint8_t[_vend_size];
        std::memcpy(_vend, other->_vend, _vend_size);
    }
    else
        _vend = 0;
}

Tins::PDU *Tins::BootP::clone_pdu() const {
    BootP *new_pdu = new BootP();
    new_pdu->copy_bootp_fields(this);
    return new_pdu;
}
