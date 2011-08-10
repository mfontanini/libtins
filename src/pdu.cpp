#include <cassert>
#include "pdu.h"

Tins::PDU::PDU(uint32_t flag, PDU *next_pdu) : _flag(flag), _inner_pdu(next_pdu) {
    
}

Tins::PDU::~PDU() {
    delete _inner_pdu;
}

uint32_t Tins::PDU::size() const {
    uint32_t sz = header_size() + trailer_size();
    const PDU *ptr(_inner_pdu);
    while(ptr) {
        sz += ptr->header_size() + trailer_size();
        ptr = ptr->inner_pdu();
    }
    return sz;
}

void Tins::PDU::flag(uint32_t new_flag) {
    _flag = new_flag;
}

void Tins::PDU::inner_pdu(PDU *next_pdu) {
    delete _inner_pdu;
    _inner_pdu = next_pdu;
}

uint8_t *Tins::PDU::serialize() {
    uint32_t sz(size());
    uint8_t *buffer = new uint8_t[sz];
    serialize(buffer, sz);
    return buffer;
}

void Tins::PDU::serialize(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = header_size() + trailer_size();
    write_serialization(buffer, total_sz);
    /* Must not happen... */
    assert(total_sz >= sz);
    if(_inner_pdu)
        _inner_pdu->serialize(buffer + header_size(), total_sz - sz);
}

