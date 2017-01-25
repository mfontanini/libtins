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

#ifndef TINS_CXXSTD_H
#define TINS_CXXSTD_H

#include "config.h"

#include <memory>

#ifdef __GXX_EXPERIMENTAL_CXX0X__
    #define TINS_CXXSTD_GCC_FIX 1
#else
    #define TINS_CXXSTD_GCC_FIX 0
#endif // __GXX_EXPERIMENTAL_CXX0X__

#if !defined(TINS_IS_CXX11) && defined(TINS_HAVE_CXX11)
#define TINS_IS_CXX11 (__cplusplus > 199711L || TINS_CXXSTD_GCC_FIX == 1 || _MSC_VER >= 1800)
#elif !defined(TINS_IS_CXX11)
#define TINS_IS_CXX11 0
#endif  // TINS_IS_CXX11

namespace Tins{
namespace Internals {
template<typename T>
struct smart_ptr {
#if TINS_IS_CXX11
    typedef std::unique_ptr<T> type;
#else
    typedef std::auto_ptr<T> type;
#endif
};

template<class T> void unused(const T&) { }
}
}

#endif // TINS_CXXSTD_H
