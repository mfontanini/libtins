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

#ifndef TINS_TYPE_TRAITS_H
#define TINS_TYPE_TRAITS_H

#include <stdint.h>

namespace Tins {
namespace Internals {
/**
 * \cond
 */

template<bool, typename T = void>
struct enable_if {
    typedef T type;
};

template<typename T>
struct enable_if<false, T> {

};

template<typename T>
struct is_unsigned_integral {
    static const bool value = false;
};

template<>
struct is_unsigned_integral<uint8_t> {
    static const bool value = true;
};

template<>
struct is_unsigned_integral<uint16_t> {
    static const bool value = true;
};

template<>
struct is_unsigned_integral<uint32_t> {
    static const bool value = true;
};

template<>
struct is_unsigned_integral<uint64_t> {
    static const bool value = true;
};

/**
 * \endcond
 */

} // Internals
} // Tins

#endif // TINS_TYPE_TRAITS_H
