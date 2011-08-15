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


#include <cstring>
#include <cassert>
#include <netinet/in.h>
#include "arp.h"
#include "utils.h"


using namespace std;

Tins::ARP::ARP() : PDU(0x0608) {
    std::memset(&_arp, 0, sizeof(arphdr));
    _arp.ar_hrd = 0x0100;
    _arp.ar_pro = 0x0008;
    _arp.ar_hln = 6;
    _arp.ar_pln = 4;
}

void Tins::ARP::set_arp_request(const string &ip_dst, const string &ip_src, const string &hw_src) {
    _arp.ar_tip = Utils::resolve_ip(ip_dst);
    _arp.ar_sip = Utils::resolve_ip(ip_src);
    _arp.ar_op = REQUEST;
}

uint32_t Tins::ARP::header_size() const {
    return sizeof(arphdr);
}

void Tins::ARP::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) {
    assert(total_sz >= sizeof(arphdr));
    memcpy(buffer, &_arp, sizeof(arphdr));
}

