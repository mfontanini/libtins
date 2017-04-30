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

#include "detail/icmp_extension_helpers.h"
#include "memory_helpers.h"
#include "pdu.h"
#include "icmp_extension.h"

using Tins::Memory::InputMemoryStream;

namespace Tins {
namespace Internals {

uint32_t get_padded_icmp_inner_pdu_size(const PDU* inner_pdu, uint32_t pad_alignment) {
        // This gets the size of the next pdu, padded to the next 32 bit word boundary
    if (inner_pdu) {
        uint32_t inner_pdu_size = inner_pdu->size();
        uint32_t padding = inner_pdu_size % pad_alignment;
        inner_pdu_size = padding ? (inner_pdu_size - padding + pad_alignment) : inner_pdu_size;
        return inner_pdu_size;
    }
    else {
        return 0;
    }
}

void try_parse_icmp_extensions(InputMemoryStream& stream,
                               uint32_t payload_length,
                               ICMPExtensionsStructure& extensions) {
    if (!stream) {
        return;
    }
    // Check if this is one of the types defined in RFC 4884
    const uint32_t minimum_payload = ICMPExtensionsStructure::MINIMUM_ICMP_PAYLOAD;
    // Check if we actually have this amount of data and whether it's more than
    // the minimum encapsulated packet size
    const uint8_t* extensions_ptr;
    uint32_t extensions_size;
    if (stream.can_read(payload_length) && payload_length >= minimum_payload) {
        extensions_ptr = stream.pointer() + payload_length;
        extensions_size = stream.size() - payload_length;
    }
    else if (stream.can_read(minimum_payload)) {
        // This packet might be non-rfc compliant. In that case the length
        // field can contain garbage.
        extensions_ptr = stream.pointer() + minimum_payload;
        extensions_size = stream.size() - minimum_payload;
    }
    else {
        // No more special cases, this doesn't have extensions
        return;
    }
    if (ICMPExtensionsStructure::validate_extensions(extensions_ptr, extensions_size)) {
        extensions = ICMPExtensionsStructure(extensions_ptr, extensions_size);
        stream.size(stream.size() - extensions_size);
    }
}

} // Internals
} // Tins
