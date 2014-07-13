/*
 * Copyright (c) 2014, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <cstring>
#include "ipsec.h"
#include "internals.h"
#include "rawpdu.h"

namespace Tins {

IPSecAH::IPSecAH() 
: _header(), _icv(4) {
    length(2);
}

IPSecAH::IPSecAH(const uint8_t *buffer, uint32_t total_sz) {
    // At least size for the header + 32bits of ICV
    if(total_sz < sizeof(_header) + sizeof(uint32_t))
        throw malformed_packet();
    std::memcpy(&_header, buffer, sizeof(_header));
    const uint32_t ah_len = 4 * (static_cast<uint16_t>(length()) + 2);
    if(ah_len > total_sz)
        throw malformed_packet();
    _icv.assign(buffer + sizeof(_header), buffer + ah_len);
    buffer += ah_len;
    total_sz -= ah_len;
    if(total_sz) {
        inner_pdu(
            Internals::pdu_from_flag(
                static_cast<Constants::IP::e>(next_header()),
                buffer, 
                total_sz,
                true
            )
        );
    }
}

void IPSecAH::next_header(uint8_t new_next_header) {
    _header.next_header = new_next_header;
}

void IPSecAH::length(uint8_t new_length) {
    _header.length = new_length;
}

void IPSecAH::spi(uint32_t new_spi) {
    _header.spi = Endian::host_to_be(new_spi);
}

void IPSecAH::seq_number(uint32_t new_seq_number) {
    _header.seq_number = Endian::host_to_be(new_seq_number);
}

void IPSecAH::icv(const byte_array &new_icv) {
    _icv = new_icv;
}

uint32_t IPSecAH::header_size() const {
    return sizeof(_header) + _icv.size();
}

void IPSecAH::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    if(inner_pdu())
        next_header(Internals::pdu_flag_to_ip_type(inner_pdu()->pdu_type()));
    std::memcpy(buffer, &_header, sizeof(_header));
    std::copy(  
        _icv.begin(),
        _icv.end(),
        buffer + sizeof(_header)
    );
}

// IPSecESP

IPSecESP::IPSecESP() 
: _header()
{

}

IPSecESP::IPSecESP(const uint8_t *buffer, uint32_t total_sz) {
    if(total_sz < sizeof(_header))
        throw malformed_packet();
    std::memcpy(&_header, buffer, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    if(total_sz) {
        inner_pdu(new RawPDU(buffer, total_sz));
    }
}

void IPSecESP::spi(uint32_t new_spi) {
    _header.spi = Endian::host_to_be(new_spi);
}

void IPSecESP::seq_number(uint32_t new_seq_number) {
    _header.seq_number = Endian::host_to_be(new_seq_number);
}

uint32_t IPSecESP::header_size() const {
    return sizeof(_header);
}

void IPSecESP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    std::memcpy(buffer, &_header, sizeof(_header));
}

}
