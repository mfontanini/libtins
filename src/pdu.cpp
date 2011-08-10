#include <cassert.h>
#include "pdu.h"


PDU::PDU(uint32_t pdu_flag, , PDU *next_pdu) : _pdu_flag(pdu_flag), _inner_pdu(next_pdu) {
    
}

PDU::~PDU() {
    delete _inner_pdu;
}

uint32_t PDU::size() const {
    uint32_t sz = header_size() + trailer_size();
    PDU *ptr(_inner_pdu);
    while(ptr) {
        sz += ptr->header_size() + trailer_size();
        ptr = ptr->inner_pdu();
    }
    return sz;
}

void PDU::inner_pdu(PDU *next_pdu) {
    delete _inner_pdu;
    _inner_pdu = next_pdu;
}

uint8_t *PDU::serialize() {
    uint32_t sz(size());
    uint8_t *buffer = new uint8_t[sz];
    
}

void PDU::serialize(uint8_t *buffer, uint32_t total_sz) {
    uint32_t sz = header_size() + trailer_size();
    write_serialization(buffer, total_sz);
    /* Must not happen... */
    std::assert(total_sz >= sz);
    if(_inner_pdu)
        _inner_pdu->serialize(buffer + header_size(), total_sz - sz);
}
