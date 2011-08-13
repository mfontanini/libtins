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

#ifndef __UTILS_H
#define __UTILS_H


#include <string>
#include <stdint.h>

namespace Tins {
    /* Utils namespace. */
    namespace Utils {
        uint32_t ip_to_int(const std::string &ip);
        std::string ip_to_string(uint32_t ip);

        uint32_t resolve_ip(const std::string &to_resolve);

        inline uint32_t net_to_host_l(uint32_t address) {
            return (((address & 0xff000000) >> 24) | ((address & 0x00ff0000) >> 8)  |
                    ((address & 0x0000ff00) << 8)  | ((address & 0x000000ff) << 24));
        }

        inline uint32_t net_to_host_s(uint16_t address) {
            return ((address & 0xff00) >> 8)  | ((address & 0x00ff) << 8);
        }

        uint32_t crc32(uint8_t* data, uint32_t data_size);
    };
};

#endif
