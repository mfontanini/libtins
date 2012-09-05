/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
 
#ifndef TINS_ENDIANNESS_H
#define TINS_ENDIANNESS_H

#include <stdint.h>
#ifndef WIN32
    #include <endian.h>
#endif

#define TINS_IS_LITTLE_ENDIAN (__BYTE_ORDER == __LITTLE_ENDIAN)
#define TINS_IS_BIG_ENDIAN (__BYTE_ORDER == __BIG_ENDIAN)

namespace Tins {
namespace Endian {
    /** 
     * \brief Changes a 16-bit integral value's endianess.
     *
     * \param data The data to convert.
     */
    inline uint16_t change_endian(uint16_t data) {
        return ((data & 0xff00) >> 8)  | ((data & 0x00ff) << 8);
    }
    
    /**
     * \brief Changes a 32-bit integral value's endianess.
     *
     * \param data The data to convert.
     */
    inline uint32_t change_endian(uint32_t data) {
        return (((data & 0xff000000) >> 24) | ((data & 0x00ff0000) >> 8)  |
                ((data & 0x0000ff00) << 8)  | ((data & 0x000000ff) << 24));
    }
    
    /**
     * \brief Changes a 64-bit integral value's endianess.
     *
     * \param data The data to convert.
     */
     inline uint64_t change_endian(uint64_t data) {
        return (((uint64_t)(change_endian((uint32_t)((data << 32) >> 32))) << 32) |
                (change_endian(((uint32_t)(data >> 32)))));
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
