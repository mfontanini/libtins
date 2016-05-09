/*
 * Copyright (c) 2016, Matias Fontanini
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

#ifdef TINS_HAVE_DOT11

#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <utility>
#include "macros.h"
#include "exceptions.h"

#ifndef _WIN32
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
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

const Dot11::address_type Dot11::BROADCAST = "ff:ff:ff:ff:ff:ff";

Dot11::Dot11(const address_type& dst_hw_addr) 
: header_(), options_size_(0) {
    addr1(dst_hw_addr);
}

Dot11::Dot11(const dot11_header* header_ptr)
: header_(), options_size_(0) {

}

Dot11::Dot11(const uint8_t* buffer, uint32_t total_sz) 
: options_size_(0) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
}

void Dot11::parse_tagged_parameters(InputMemoryStream& stream) {
    if (stream) {
        while (stream.size() >= 2) {
            OptionTypes opcode = static_cast<OptionTypes>(stream.read<uint8_t>());
            uint8_t length = stream.read<uint8_t>();
            if (!stream.can_read(length)) {
                throw malformed_packet();
            }
            add_tagged_option(opcode, length, stream.pointer());
            stream.skip(length);
        }
    }
}

void Dot11::add_tagged_option(OptionTypes opt, uint8_t len, const uint8_t* val) {
    uint32_t opt_size = len + sizeof(uint8_t) * 2;
    options_.push_back(option((uint8_t)opt, val, val + len));
    options_size_ += opt_size;
}

void Dot11::internal_add_option(const option& opt) {
    options_size_ += static_cast<uint32_t>(opt.data_size() + sizeof(uint8_t) * 2);
}

bool Dot11::remove_option(OptionTypes type) {
    options_type::iterator iter = search_option_iterator(type);
    if (iter == options_.end()) {
        return false;
    }
    options_size_ -= static_cast<uint32_t>(iter->data_size() + sizeof(uint8_t) * 2);
    options_.erase(iter);
    return true;
}

void Dot11::add_option(const option& opt) {
    internal_add_option(opt);
    options_.push_back(opt);
}

const Dot11::option* Dot11::search_option(OptionTypes type) const {
    // Search for the iterator. If we found something, return it, otherwise return nullptr.
    options_type::const_iterator iter = search_option_iterator(type);
    return (iter != options_.end()) ? &*iter : 0;
}

Dot11::options_type::const_iterator Dot11::search_option_iterator(OptionTypes type) const {
    Internals::option_type_equality_comparator<option> comparator(static_cast<uint8_t>(type));
    return find_if(options_.begin(), options_.end(), comparator);
}

Dot11::options_type::iterator Dot11::search_option_iterator(OptionTypes type) {
    Internals::option_type_equality_comparator<option> comparator(static_cast<uint8_t>(type));
    return find_if(options_.begin(), options_.end(), comparator);
}

void Dot11::protocol(small_uint<2> new_proto) {
    header_.control.protocol = new_proto;
}

void Dot11::type(small_uint<2> new_type) {
    header_.control.type = new_type;
}

void Dot11::subtype(small_uint<4> new_subtype) {
    header_.control.subtype = new_subtype;
}

void Dot11::to_ds(small_uint<1> new_value) {
    header_.control.to_ds = (new_value)? 1 : 0;
}

void Dot11::from_ds(small_uint<1> new_value) {
    header_.control.from_ds = (new_value)? 1 : 0;
}

void Dot11::more_frag(small_uint<1> new_value) {
    header_.control.more_frag = (new_value)? 1 : 0;
}

void Dot11::retry(small_uint<1> new_value) {
    header_.control.retry = (new_value)? 1 : 0;
}

void Dot11::power_mgmt(small_uint<1> new_value) {
    header_.control.power_mgmt = (new_value)? 1 : 0;
}

void Dot11::wep(small_uint<1> new_value) {
    header_.control.wep = (new_value)? 1 : 0;
}

void Dot11::order(small_uint<1> new_value) {
    header_.control.order = (new_value)? 1 : 0;
}

void Dot11::duration_id(uint16_t new_duration_id) {
    header_.duration_id = Endian::host_to_le(new_duration_id);
}

void Dot11::addr1(const address_type& new_addr1) {
    new_addr1.copy(header_.addr1);
}

uint32_t Dot11::header_size() const {
    return sizeof(header_) + options_size_;
}

#ifndef _WIN32
void Dot11::send(PacketSender& sender, const NetworkInterface& iface) {
    if (!iface) {
        throw invalid_interface();
    }
    
    #if !defined(BSD) && !defined(__FreeBSD_kernel__)
        sockaddr_ll addr;

        memset(&addr, 0, sizeof(struct sockaddr_ll));

        addr.sll_family = Endian::host_to_be<uint16_t>(PF_PACKET);
        addr.sll_protocol = Endian::host_to_be<uint16_t>(ETH_P_ALL);
        addr.sll_halen = 6;
        addr.sll_ifindex = iface.id();
        memcpy(&(addr.sll_addr), header_.addr1, 6);
        sender.send_l2(*this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr), iface);
    #else
        sender.send_l2(*this, 0, 0, iface);
    #endif
}
#endif // _WIN32

void Dot11::write_serialization(uint8_t* buffer, uint32_t total_sz, const PDU* parent) {
    OutputMemoryStream stream(buffer, total_sz);
    stream.write(header_);
    write_ext_header(stream);
    write_fixed_parameters(stream);
    for (std::list<option>::const_iterator it = options_.begin(); it != options_.end(); ++it) {
        stream.write<uint8_t>(it->option());
        stream.write<uint8_t>(it->length_field());
        stream.write(it->data_ptr(), it->data_size());
    }
}

Dot11* Dot11::from_bytes(const uint8_t* buffer, uint32_t total_sz) {
    // We only need the control field, the length of the PDU will depend on the flags set.
    
    // This should be sizeof(dot11_header::control), but gcc 4.2 complains
    if (total_sz < 2) {
        throw malformed_packet();
    }
    const dot11_header* hdr = (const dot11_header*)buffer;
    if (hdr->control.type == MANAGEMENT) {
        switch (hdr->control.subtype) {
            case BEACON:
                return new Dot11Beacon(buffer, total_sz);
            case DISASSOC:
                return new Dot11Disassoc(buffer, total_sz);
            case ASSOC_REQ:
                return new Dot11AssocRequest(buffer, total_sz);
            case ASSOC_RESP:
                return new Dot11AssocResponse(buffer, total_sz);
            case REASSOC_REQ:
                return new Dot11ReAssocRequest(buffer, total_sz);
            case REASSOC_RESP:
                return new Dot11ReAssocResponse(buffer, total_sz); 
            case AUTH:
                return new Dot11Authentication(buffer, total_sz); 
            case DEAUTH:
                return new Dot11Deauthentication(buffer, total_sz); 
            case PROBE_REQ:
                return new Dot11ProbeRequest(buffer, total_sz); 
            case PROBE_RESP:
                return new Dot11ProbeResponse(buffer, total_sz); 
            default: 
                break;
        };
    }
    else if (hdr->control.type == DATA) {
        if (hdr->control.subtype <= 4) {
            return new Dot11Data(buffer, total_sz);
        }
        else {
            return new Dot11QoSData(buffer, total_sz);
        }
    }
    else if (hdr->control.type == CONTROL) {
        switch (hdr->control.subtype) {
            case ACK:
                return new Dot11Ack(buffer, total_sz);
            case CF_END:
                return new Dot11CFEnd(buffer, total_sz);
            case CF_END_ACK:
                return new Dot11EndCFAck(buffer, total_sz);
            case PS:
                return new Dot11PSPoll(buffer, total_sz);
            case RTS:
                return new Dot11RTS(buffer, total_sz);
            case BLOCK_ACK:
                return new Dot11BlockAck(buffer, total_sz);
            case BLOCK_ACK_REQ:
                return new Dot11BlockAckRequest(buffer, total_sz);
            default:
                break;
        };
    }
    // Fallback to just building a dot11
    return new Dot11(buffer, total_sz);
}

} // Tins

#endif // TINS_HAVE_DOT11
