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

#include <sstream>
#include <iomanip>
#include <algorithm>
#include "hw_address.h"
#include "exceptions.h"

using std::string;
using std::ostream;
using std::hex;
using std::ostringstream;
using std::lexicographical_compare;
using std::equal;

namespace Tins {
namespace Internals {

void storage_to_string(ostream& output, uint8_t value) {
    output << hex;
    if (value < 0x10) {
        output << '0';
    }
    output << (unsigned)value;
}

string hw_address_to_string(const uint8_t* ptr, size_t count) {
    ostringstream output;
    for (size_t i = 0; i < count; ++i) {
        if (i != 0) {
            output << ":";
        }
        storage_to_string(output, ptr[i]);
    }
    return output.str();
}

void string_to_hw_address(const string& hw_addr, uint8_t* output, size_t output_size)  {
    unsigned i = 0;
    size_t count = 0;
    uint8_t tmp;
    while (i < hw_addr.size() && count < output_size) {
        const unsigned end = i+2;
        tmp = 0;
        while (i < end) {
            if (hw_addr[i] >= 'a' && hw_addr[i] <= 'f') {
                tmp = (tmp << 4) | (hw_addr[i] - 'a' + 10);
            }
            else if (hw_addr[i] >= 'A' && hw_addr[i] <= 'F') {
                tmp = (tmp << 4) | (hw_addr[i] - 'A' + 10);
            }
            else if (hw_addr[i] >= '0' && hw_addr[i] <= '9') {
                tmp = (tmp << 4) | (hw_addr[i] - '0');
            }
            else if (hw_addr[i] == ':') {
                break;
            }
            else {
                throw invalid_address();
            }
            i++;
        }
        *(output++) = tmp;
        count++;
        if (i < hw_addr.size()) {
            if (hw_addr[i] == ':') {
                i++;
            }
            else {
                throw invalid_address();
            }
        }
    }
    while (count++ < output_size) {
        *(output++) = 0;
    }
}

bool hw_address_equal_compare(const uint8_t* start1, const uint8_t* end1,
                              const uint8_t* start2) {
    return equal(start1, end1, start2);
}

bool hw_address_lt_compare(const uint8_t* start1, const uint8_t* end1,
                           const uint8_t* start2, const uint8_t* end2) {
    return lexicographical_compare(start1, end1, start2, end2);
}

} // Internals
} // Tins
