/*
 * Copyright (c) 2016, Matias Fontanini
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

#ifndef TINS_MACROS_H
#define TINS_MACROS_H

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    #include <sys/param.h>
#endif

#include "config.h"

// Check if this is Visual Studio
#ifdef _MSC_VER
    // This is Visual Studio
    #define TINS_BEGIN_PACK __pragma( pack(push, 1) )
    #define TINS_END_PACK __pragma( pack(pop) )
    #define TINS_PACKED(DECLARATION) __pragma( pack(push, 1) ) DECLARATION __pragma( pack(pop) )
    #define TINS_DEPRECATED(func) __declspec(deprecated) func
    #define TINS_NOEXCEPT
    #define TINS_LIKELY(x) (x)
    #define TINS_UNLIKELY(x) (x)
#else
    // Not Visual Studio. Assume this is gcc compatible
    #define TINS_BEGIN_PACK 
    #define TINS_END_PACK __attribute__((packed))
    #define TINS_PACKED(DECLARATION) DECLARATION __attribute__((packed))
    #define TINS_DEPRECATED(func) func __attribute__ ((deprecated))
    #define TINS_NOEXCEPT noexcept
    #define TINS_LIKELY(x) __builtin_expect((x),1)
    #define TINS_UNLIKELY(x) __builtin_expect((x),0)
#endif // _MSC_VER

// If libtins was built into a shared library
#if defined(_WIN32) && !defined(TINS_STATIC)
    // Export/import symbols, depending on whether we're compiling or consuming the lib
    #ifdef tins_EXPORTS
        #define TINS_API __declspec(dllexport)
    #else
        #define TINS_API __declspec(dllimport)
    #endif // tins_EXPORTS
#else 
    // Otherwise, default this to an empty macro
    #define TINS_API
#endif // _WIN32 && !TINS_STATIC

#endif // TINS_MACROS_H
