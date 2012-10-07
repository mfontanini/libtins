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

#ifndef TINS_SMALL_UINT_H
#define TINS_SMALL_UINT_H

#include <stdint.h>
#include <stdexcept>

namespace Tins {
template<size_t n>
class small_uint {
private:
    template<bool cond, typename OnTrue, typename OnFalse>
    struct if_then_else {
        typedef OnTrue type;
    };

    template<typename OnTrue, typename OnFalse>
    struct if_then_else<false, OnTrue, OnFalse>  {
        typedef OnFalse type;
    };

    template<size_t i>
    struct best_type {
        typedef typename if_then_else<
            (i <= 8),
            uint8_t,
            typename if_then_else<
                (i <= 16),
                uint16_t,
                typename if_then_else<
                    (i <= 32),
                    uint32_t,
                    uint64_t
                >::type
            >::type
        >::type type;
    };
    
    template<uint64_t base, uint64_t pow>
    struct power {
        static const uint64_t value = base * power<base, pow - 1>::value;
    };
    
    template<uint64_t base>
    struct power<base, 0> {
        static const uint64_t value = 1;
    };
public:
    class value_to_large : public std::exception {
    public:
        const char *what() const throw() {
            return "Value is too large";
        }
    };

    typedef typename best_type<n>::type repr_type;
    static const repr_type max_value = power<2, n>::value - 1;
    
    small_uint() : value() {}
    
    small_uint(repr_type val) {
        if(val > max_value)
            throw value_to_large();
        value = val;
    }
    
    operator repr_type() const {
        return value;
    }
private:
    repr_type value;
};

} // namespace Tins
#endif // TINS_SMALL_UINT_H
