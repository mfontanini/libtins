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

#include <stdexcept>
#include <cstring>
#include "exceptions.h"
#include "pktap.h"
#include "internals.h"

namespace Tins {

PKTAP::PKTAP(const uint8_t* buffer, uint32_t total_sz)
{
    if (total_sz < sizeof(pktap_header)) {
        throw malformed_packet();
    }
    memcpy(&header_, buffer, sizeof(header_));
    uint32_t header_length = header_.length;
    if (header_length > total_sz) {
        throw malformed_packet();
    }
    buffer += header_length;
    total_sz -= header_length;
    if (header_.next && total_sz > 0) {
        inner_pdu(
            Internals::pdu_from_dlt_flag(
                header_.dlt, 
                buffer, 
                total_sz
            )
        );
    }
}

uint32_t PKTAP::header_size() const
{
    return sizeof(header_);
}

void PKTAP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent)
{
    throw std::runtime_error("PKTAP cannot be serialized");
}

} // Tins
