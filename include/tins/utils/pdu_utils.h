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

#ifndef TINS_PDU_UTILS_H
#define TINS_PDU_UTILS_H

#include <tins/macros.h>
#include <tins/pdu.h>
#include <tins/detail/type_traits.h>

namespace Tins {
namespace Utils {

/**
 * \brief Converts a PDUType to a string.
 * \param pduType The PDUType to be converted.
 * \return A string representation, for example "DOT11_QOS_DATA".
 */
TINS_API std::string to_string(PDU::PDUType pduType);

template <typename T>
struct is_pdu {  
    template <typename U>
    static char test(typename U::PDUType*);
     
    template <typename U>
    static long test(...);
 
    static const bool value = sizeof(test<T>(0)) == 1;
};

/**
 * Returns the argument.
 */
inline PDU& dereference_until_pdu(PDU& pdu) {
    return pdu;
}

/**
 * \brief Dereferences the parameter until a PDU is found.
 * 
 * This function dereferences the parameter until a PDU object
 * is found. When it's found, it is returned. 
 * 
 * \param value The parameter to be dereferenced.
 */
template<typename T> 
inline typename Internals::enable_if<!is_pdu<T>::value, PDU&>::type 
dereference_until_pdu(T& value) {
    return dereference_until_pdu(*value);
}

} // Utils
} // Tins


#endif // TINS_PDU_UTILS_H
