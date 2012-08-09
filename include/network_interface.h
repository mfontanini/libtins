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
 
#ifndef TINS_NETWORK_INTERFACE_H
#define TINS_NETWORK_INTERFACE_H

#include <string>
#include <stdint.h>
#include "hwaddress.h"

namespace Tins {
class NetworkInterface {
public:
    typedef uint32_t id_type;
    typedef HWAddress<6> address_type;

    NetworkInterface(const std::string &name);
    NetworkInterface(id_type id);
    
    id_type id() const {
        return iface_id;
    }
    
    address_type address();
    
    bool operator==(const NetworkInterface &rhs) const {
        return iface_id == rhs.iface_id;
    }
    
    bool operator!=(const NetworkInterface &rhs) const {
        return !(*this == rhs);
    }
private:
    id_type iface_id;
};
}
#endif // TINS_NETWORK_INTERFACE_H
