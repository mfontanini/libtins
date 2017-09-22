/*
 * Copyright (c) 2017, Matias Fontanini
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

#ifndef TINS_PDU_HELPERS_H
#define TINS_PDU_HELPERS_H

#include <tins/constants.h>
#include <tins/config.h>
#include <tins/pdu.h>

/**
 * \cond
 */

namespace Tins {
namespace Internals {

PDU* pdu_from_flag(Constants::Ethernet::e flag, const uint8_t* buffer,
                   uint32_t size, bool rawpdu_on_no_match = true);
PDU* pdu_from_flag(Constants::IP::e flag, const uint8_t* buffer,
                   uint32_t size, bool rawpdu_on_no_match = true);
#ifdef TINS_HAVE_PCAP
PDU* pdu_from_dlt_flag(int flag, const uint8_t* buffer,
                       uint32_t size, bool rawpdu_on_no_match = true);
#endif // TINS_HAVE_PCAP
PDU* pdu_from_flag(PDU::PDUType type, const uint8_t* buffer, uint32_t size);

Constants::Ethernet::e pdu_flag_to_ether_type(PDU::PDUType flag);
PDU::PDUType ether_type_to_pdu_flag(Constants::Ethernet::e flag);
Constants::IP::e pdu_flag_to_ip_type(PDU::PDUType flag);
PDU::PDUType ip_type_to_pdu_flag(Constants::IP::e flag);

inline bool is_dot3(const uint8_t* ptr, size_t sz) {
    return (sz >= 13 && ptr[12] < 8);
}

} // Internals
} // Tins

/**
 * \endcond
 */

#endif // TINS_PDU_HELPERS_H
