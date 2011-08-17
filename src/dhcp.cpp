#include <cstring>
#include <cassert>
#include <iostream> //borrame
#include "utils.h"
#include "dhcp.h"

const uint32_t Tins::DHCP::MAX_DHCP_SIZE = 312;

/* Magic cookie: uint32_t.
 * end of options: 1 byte. */
Tins::DHCP::DHCP() : _size(sizeof(uint32_t) + 1) {
    opcode(BOOTREQUEST);
    htype(1); //ethernet
    hlen(6);
}

Tins::DHCP::DHCPOption::DHCPOption(uint8_t opt, uint8_t len, uint8_t *val) : option(opt), length(len) {
    value = new uint8_t[len];
    std::memcpy(value, val, len);
}

bool Tins::DHCP::add_option(Options opt, uint8_t len, uint8_t *val) {
    uint32_t opt_size = len + (sizeof(uint8_t) << 1);
    if(_size + opt_size > MAX_DHCP_SIZE)
        return false;
    _options.push_back(DHCPOption((uint8_t)opt, len, val));
    _size += opt_size;
    return true;
}

void Tins::DHCP::add_type_option(Flags type) {
    add_option(DHCP_MESSAGE_TYPE, 1, (uint8_t*)&type);
}

uint32_t Tins::DHCP::header_size() const {
    return BootP::header_size() - vend_size() + _size;
}

void Tins::DHCP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= header_size());
    uint8_t *result = new uint8_t[_size], *ptr = result + sizeof(uint32_t);
    *((uint32_t*)result) = Utils::net_to_host_l(0x63825363);
    for(std::list<DHCPOption>::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        *(ptr++) = it->option;
        *(ptr++) = it->length;
        std::memcpy(ptr++, it->value, it->length);
    }
    result[_size-1] = END;
    vend(result, _size);
    BootP::write_serialization(buffer, total_sz, parent);
}

