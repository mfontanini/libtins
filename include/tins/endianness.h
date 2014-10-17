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
 
#ifndef TINS_ENDIANNESS_H
#define TINS_ENDIANNESS_H

#include <stdint.h>
#include "macros.h"

#if defined(__APPLE__)
    #include <sys/types.h>
    #define TINS_IS_LITTLE_ENDIAN (BYTE_ORDER == LITTLE_ENDIAN)
    #define TINS_IS_BIG_ENDIAN (BYTE_ORDER == BIG_ENDIAN)
#elif defined(BSD)
    #include <sys/endian.h>
    #define TINS_IS_LITTLE_ENDIAN (_BYTE_ORDER == _LITTLE_ENDIAN)
    #define TINS_IS_BIG_ENDIAN (_BYTE_ORDER == _BIG_ENDIAN)
#elif defined(WIN32)
    // Assume windows == little endian. fixme later
    #define TINS_IS_LITTLE_ENDIAN 1
    #define TINS_IS_BIG_ENDIAN 0
#else
    #include <endian.h>
    #define TINS_IS_LITTLE_ENDIAN (__BYTE_ORDER == __LITTLE_ENDIAN)
    #define TINS_IS_BIG_ENDIAN (__BYTE_ORDER == __BIG_ENDIAN)
#endif



namespace Tins {
namespace Endian {
    /** 
     * \brief "Changes" a 8-bit integral value's endianess. This is an
     * identity function.
     *
     * \param data The data to convert.
     */
    inline uint8_t do_change_endian(uint8_t data) {
        return data;
    }
    
    /** 
     * \brief Changes a 16-bit integral value's endianess.
     *
     * \param data The data to convert.
     */
    inline uint16_t do_change_endian(uint16_t data) {
        return ((data & 0xff00) >> 8)  | ((data & 0x00ff) << 8);
    }
    
    /**
     * \brief Changes a 32-bit integral value's endianess.
     *
     * \param data The data to convert.
     */
    inline uint32_t do_change_endian(uint32_t data) {
        return (((data & 0xff000000) >> 24) | ((data & 0x00ff0000) >> 8)  |
                ((data & 0x0000ff00) << 8)  | ((data & 0x000000ff) << 24));
    }
    
    /**
     * \brief Changes a 64-bit integral value's endianess.
     *
     * \param data The data to convert.
     */
     inline uint64_t do_change_endian(uint64_t data) {
        return (((uint64_t)(do_change_endian((uint32_t)(data & 0xffffffff))) << 32) |
                (do_change_endian(((uint32_t)(data >> 32)))));
     }
     
    /**
     * \cond
     */
    
    // Helpers to convert
    template<typename T>
    struct conversion_dispatch_helper {
        static T dispatch(T data) {
            return do_change_endian(data);
        }
    };
    
    
    template<size_t>
    struct conversion_dispatcher;
    
    template<>
    struct conversion_dispatcher<sizeof(uint8_t)> 
    : public conversion_dispatch_helper<uint8_t> 
    { };
    
    template<>
    struct conversion_dispatcher<sizeof(uint16_t)> 
    : public conversion_dispatch_helper<uint16_t> 
    { };
    
    template<>
    struct conversion_dispatcher<sizeof(uint32_t)> 
    : public conversion_dispatch_helper<uint32_t> 
    { };
    
    template<>
    struct conversion_dispatcher<sizeof(uint64_t)> 
    : public conversion_dispatch_helper<uint64_t> 
    { };
    
    /**
     * \endcond
     */
    
    /**
     * \brief Changes an integral value's endianess.
     * 
     * This dispatchs to the corresponding function.
     *
     * \param data The data to convert.
     */ 
     template<typename T>
     inline T change_endian(T data) {
         return conversion_dispatcher<sizeof(T)>::dispatch(data);
     }
    
    #if TINS_IS_LITTLE_ENDIAN
        /** 
         * \brief Convert any integral type to big endian.
         *
         * \param data The data to convert.
         */
        template<typename T>
        inline T host_to_be(T data) {
            return change_endian(data);
        }
         
        /**
         * \brief Convert any integral type to little endian.
         *
         * On little endian platforms, the parameter is simply returned.
         * 
         * \param data The data to convert.
         */
         template<typename T>
         inline T host_to_le(T data) {
             return data;
         }
         
        /**
         * \brief Convert any big endian value to the host's endianess.
         * 
         * \param data The data to convert.
         */
         template<typename T>
         inline T be_to_host(T data) {
             return change_endian(data);
         }
         
        /**
         * \brief Convert any little endian value to the host's endianess.
         * 
         * \param data The data to convert.
         */
         template<typename T>
         inline T le_to_host(T data) {
             return data;
         }
    #elif TINS_IS_BIG_ENDIAN
        /** 
         * \brief Convert any integral type to big endian.
         *
         * \param data The data to convert.
         */
        template<typename T>
        inline T host_to_be(T data) {
            return data;
        }
         
        /**
         * \brief Convert any integral type to little endian.
         *
         * On little endian platforms, the parameter is simply returned.
         * 
         * \param data The data to convert.
         */
         template<typename T>
         inline T host_to_le(T data) {
             return change_endian(data);
         }
         
        /**
         * \brief Convert any big endian value to the host's endianess.
         * 
         * \param data The data to convert.
         */
         template<typename T>
         inline T be_to_host(T data) {
             return data;
         }
         
        /**
         * \brief Convert any little endian value to the host's endianess.
         * 
         * \param data The data to convert.
         */
         template<typename T>
         inline T le_to_host(T data) {
             return change_endian(data);
         }
    #endif
}
}

#endif // TINS_ENDIANNESS_H
