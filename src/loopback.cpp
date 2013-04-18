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

#ifndef WIN32
    #include <sys/socket.h>
    #ifdef BSD
        #include <net/if_dl.h>
        #include <netinet/in.h>
        #include <net/ethernet.h>
    #endif
#endif
#include <stdexcept>
#include <cassert>
#include <cstring>
#include "loopback.h"
#include "packet_sender.h"
#include "ip.h"
#include "llc.h"
#include "rawpdu.h"
#include "exceptions.h"

#if !defined(PF_LLC)
    // compilation fix, nasty but at least works on BSD
    #define PF_LLC 26
#endif

namespace Tins {
Loopback::Loopback()
: _family()
{
    
}
    
Loopback::Loopback(const NetworkInterface &iface, PDU *inner_pdu)
: PDU(inner_pdu), _family(), _iface(iface)
{
    
}

Loopback::Loopback(const uint8_t *buffer, uint32_t total_sz) 
{
    if(total_sz < sizeof(_family))
        throw malformed_packet();
    _family = *reinterpret_cast<const uint32_t*>(buffer);
    buffer += sizeof(uint32_t);
    total_sz -= sizeof(uint32_t);
    #ifndef WIN32
    if(total_sz) {
        switch(_family) {
            case PF_INET:
                inner_pdu(new Tins::IP(buffer, total_sz));
                break;
            case PF_LLC:
                inner_pdu(new Tins::LLC(buffer, total_sz));
                break;
            default:
                inner_pdu(new Tins::RawPDU(buffer, total_sz));
                break;
        };
    }
    #endif // WIN32
}
    
void Loopback::family(uint32_t family_id) {
    _family = family_id;
}

void Loopback::iface(const NetworkInterface &new_iface) {
    _iface = new_iface;
}

uint32_t Loopback::header_size() const {
    return sizeof(_family);
}

void Loopback::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *) 
{
    assert(total_sz >= sizeof(_family));
    if(dynamic_cast<const Tins::IP*>(inner_pdu()))
        _family = PF_INET;
    else if(dynamic_cast<const Tins::LLC*>(inner_pdu()))
        _family = PF_LLC;
    *reinterpret_cast<uint32_t*>(buffer) = _family;
}
#ifdef BSD
void Loopback::send(PacketSender &sender) {
    if(!_iface)
        throw std::runtime_error("Interface has not been set");
    
    sender.send_l2(*this, 0, 0, _iface);
}
#endif // WIN32
}
