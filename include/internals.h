/*
 * Copyright (c) 2012, Nasel
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
 
#ifndef TINS_INTERNALS_H
#define TINS_INTERNALS_H

#include <sstream>
#include <string>
#include <stdint.h>
#include "constants.h"
#include "pdu.h"

/**
 * \cond
 */
namespace Tins {
namespace Internals {
    void skip_line(std::istream &input);
    bool from_hex(const std::string &str, uint32_t &result);
    
    template<bool, typename>
    struct enable_if {
        
    };

    template<typename T>
    struct enable_if<true, T> {
        typedef T type;
    };
    
    PDU *pdu_from_flag(Constants::Ethernet::e flag, const uint8_t *buffer, 
      uint32_t size, bool rawpdu_on_no_match = true);
    
    PDU *pdu_from_flag(PDU::PDUType type, const uint8_t *buffer, uint32_t size);
    
    Constants::Ethernet::e pdu_flag_to_ether_type(PDU::PDUType flag);
}
}
/**
 * \endcond
 */

#endif
