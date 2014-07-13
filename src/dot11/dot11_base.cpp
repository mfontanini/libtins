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

#include "dot11/dot11_base.h"

#ifdef HAVE_DOT11

#include <cassert>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <utility>
#include "macros.h"
#include "exceptions.h"

#ifndef WIN32
    #if defined(__FreeBSD_kernel__) || defined(BSD) || defined(__APPLE__)
        #include <sys/types.h>
        #include <net/if_dl.h>
    #else
        #include <netpacket/packet.h>
    #endif
    #include <net/ethernet.h>
    #include <netinet/in.h>
#endif
#include "dot11.h"
#include "rawpdu.h"
#include "rsn_information.h"
#include "packet_sender.h"
#include "snap.h"

namespace Tins {
const Dot11::address_type Dot11::BROADCAST = "ff:ff:ff:ff:ff:ff";

Dot11::Dot11(const address_type &dst_hw_addr) 
: _options_size(0)
{
    memset(&_header, 0, sizeof(ieee80211_header));
    addr1(dst_hw_addr);
}

Dot11::Dot11(const ieee80211_header *header_ptr) 
{

}

Dot11::Dot11(const uint8_t *buffer, uint32_t total_sz) 
: _options_size(0) 
{
    if(total_sz < sizeof(_header))
        throw malformed_packet();
    std::memcpy(&_header, buffer, sizeof(_header));
}

void Dot11::parse_tagged_parameters(const uint8_t *buffer, uint32_t total_sz) {
    if(total_sz > 0) {
        uint8_t opcode, length;
        while(total_sz >= 2) {
            opcode = buffer[0];
            length = buffer[1];
            buffer += 2;
            total_sz -= 2;
            if(length > total_sz) {
                throw malformed_packet();
            }
            add_tagged_option((OptionTypes)opcode, length, buffer);
            buffer += length;
            total_sz -= length;
        }
    }
}

void Dot11::add_tagged_option(OptionTypes opt, uint8_t len, const uint8_t *val) {
    uint32_t opt_size = len + sizeof(uint8_t) * 2;
    _options.push_back(option((uint8_t)opt, val, val + len));
    _options_size += opt_size;
}

void Dot11::internal_add_option(const option &opt) {
    _options_size += opt.data_size() + sizeof(uint8_t) * 2;
}

void Dot11::add_option(const option &opt) {
    internal_add_option(opt);
    _options.push_back(opt);
}

const Dot11::option *Dot11::search_option(OptionTypes opt) const {
    for(std::list<option>::const_iterator it = _options.begin(); it != _options.end(); ++it)
        if(it->option() == (uint8_t)opt)
            return &(*it);
    return 0;
}

void Dot11::protocol(small_uint<2> new_proto) {
    this->_header.control.protocol = new_proto;
}

void Dot11::type(small_uint<2> new_type) {
    this->_header.control.type = new_type;
}

void Dot11::subtype(small_uint<4> new_subtype) {
    this->_header.control.subtype = new_subtype;
}

void Dot11::to_ds(small_uint<1> new_value) {
    this->_header.control.to_ds = (new_value)? 1 : 0;
}

void Dot11::from_ds(small_uint<1> new_value) {
    this->_header.control.from_ds = (new_value)? 1 : 0;
}

void Dot11::more_frag(small_uint<1> new_value) {
    this->_header.control.more_frag = (new_value)? 1 : 0;
}

void Dot11::retry(small_uint<1> new_value) {
    this->_header.control.retry = (new_value)? 1 : 0;
}

void Dot11::power_mgmt(small_uint<1> new_value) {
    this->_header.control.power_mgmt = (new_value)? 1 : 0;
}

void Dot11::wep(small_uint<1> new_value) {
    this->_header.control.wep = (new_value)? 1 : 0;
}

void Dot11::order(small_uint<1> new_value) {
    this->_header.control.order = (new_value)? 1 : 0;
}

void Dot11::duration_id(uint16_t new_duration_id) {
    this->_header.duration_id = Endian::host_to_le(new_duration_id);
}

void Dot11::addr1(const address_type &new_addr1) {
    std::copy(new_addr1.begin(), new_addr1.end(), _header.addr1);
}

uint32_t Dot11::header_size() const {
    uint32_t sz = sizeof(ieee80211_header) + _options_size;
    return sz;
}

#ifndef WIN32
void Dot11::send(PacketSender &sender, const NetworkInterface &iface) {
    if(!iface)
        throw invalid_interface();
    
    #if !defined(BSD) && !defined(__FreeBSD_kernel__)
        sockaddr_ll addr;

        memset(&addr, 0, sizeof(struct sockaddr_ll));

        addr.sll_family = Endian::host_to_be<uint16_t>(PF_PACKET);
        addr.sll_protocol = Endian::host_to_be<uint16_t>(ETH_P_ALL);
        addr.sll_halen = 6;
        addr.sll_ifindex = iface.id();
        memcpy(&(addr.sll_addr), _header.addr1, 6);
        sender.send_l2(*this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
    #else
        sender.send_l2(*this, 0, 0, iface);
    #endif
}
#endif // WIN32

void Dot11::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    #ifdef TINS_DEBUG
    assert(total_sz >= header_size());
    #endif
    memcpy(buffer, &_header, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);

    uint32_t written = write_ext_header(buffer, total_sz);
    buffer += written;
    total_sz -= written;

    uint32_t child_len = write_fixed_parameters(buffer, total_sz - _options_size);
    buffer += child_len;
    #ifdef TINS_DEBUG
    assert(total_sz >= child_len + _options_size);
    #endif
    for(std::list<option>::const_iterator it = _options.begin(); it != _options.end(); ++it) {
        *(buffer++) = it->option();
        *(buffer++) = it->length_field();
        std::copy(it->data_ptr(), it->data_ptr() + it->data_size(), buffer);
        buffer += it->data_size();
    }
}

Dot11 *Dot11::from_bytes(const uint8_t *buffer, uint32_t total_sz) {
    // We only need the control field, the length of the PDU will depend on the flags set.
    
    // This should be sizeof(ieee80211_header::control), but gcc 4.2 complains
    if(total_sz < 2)
        throw malformed_packet();
    const ieee80211_header *hdr = (const ieee80211_header*)buffer;
    Dot11 *ret = 0;
    if(hdr->control.type == MANAGEMENT) {
        if(hdr->control.subtype == BEACON)
            ret = new Dot11Beacon(buffer, total_sz);
        else if(hdr->control.subtype == DISASSOC)
            ret = new Dot11Disassoc(buffer, total_sz);
        else if(hdr->control.subtype == ASSOC_REQ)
            ret = new Dot11AssocRequest(buffer, total_sz);
        else if(hdr->control.subtype == ASSOC_RESP)
            ret = new Dot11AssocResponse(buffer, total_sz);
        else if(hdr->control.subtype == REASSOC_REQ)
            ret = new Dot11ReAssocRequest(buffer, total_sz);
        else if(hdr->control.subtype == REASSOC_RESP)
            ret = new Dot11ReAssocResponse(buffer, total_sz); 
        else if(hdr->control.subtype == AUTH)
            ret = new Dot11Authentication(buffer, total_sz); 
        else if(hdr->control.subtype == DEAUTH)
            ret = new Dot11Deauthentication(buffer, total_sz); 
        else if(hdr->control.subtype == PROBE_REQ)
            ret = new Dot11ProbeRequest(buffer, total_sz); 
        else if(hdr->control.subtype == PROBE_RESP)
            ret = new Dot11ProbeResponse(buffer, total_sz); 
    }
    else if(hdr->control.type == DATA){
        if(hdr->control.subtype <= 4)
            ret = new Dot11Data(buffer, total_sz);
        else
            ret = new Dot11QoSData(buffer, total_sz);
    }
    else if(hdr->control.type == CONTROL){
        if(hdr->control.subtype == ACK)
            ret = new Dot11Ack(buffer, total_sz);
        else if(hdr->control.subtype == CF_END)
            ret = new Dot11CFEnd(buffer, total_sz);
        else if(hdr->control.subtype == CF_END_ACK)
            ret = new Dot11EndCFAck(buffer, total_sz);
        else if(hdr->control.subtype == PS)
            ret = new Dot11PSPoll(buffer, total_sz);
        else if(hdr->control.subtype == RTS)
            ret = new Dot11RTS(buffer, total_sz);
        else if(hdr->control.subtype == BLOCK_ACK)
            ret = new Dot11BlockAck(buffer, total_sz);
        else if(hdr->control.subtype == BLOCK_ACK_REQ)
            ret = new Dot11BlockAckRequest(buffer, total_sz);
    }
    if(ret == 0)
        ret = new Dot11(buffer, total_sz);
    return ret;
}
} // namespace Tins

#endif // HAVE_DOT11
