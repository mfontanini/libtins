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

#include "dns.h"
#include "utils.h"


void Tins::DNS::id(uint16_t new_id) {
    dns.id = new_id;
}

void Tins::DNS::type(QRType new_qr) {
    dns.qr = new_qr;
}

void Tins::DNS::opcode(uint8_t new_opcode) {
    dns.opcode = new_opcode;
}

void Tins::DNS::authoritative_answer(uint8_t new_aa) {
    dns.aa = new_aa;
}

void Tins::DNS::truncated(uint8_t new_tc) {
    dns.tc = new_tc;
}

void Tins::DNS::recursion_desired(uint8_t new_rd) {
    dns.rd = new_rd;
}

void Tins::DNS::recursion_available(uint8_t new_ra) {
    dns.ra = new_ra;
}

void Tins::DNS::z(uint8_t new_z) {
    dns.z = new_z;
}

void Tins::DNS::authenticated_data(uint8_t new_ad) {
    dns.ad = new_ad;
}

void Tins::DNS::checking_disabled(uint8_t new_cd) {
    dns.cd = new_cd;
}

void Tins::DNS::rcode(uint8_t new_rcode) {
    dns.rcode = new_rcode;
}
