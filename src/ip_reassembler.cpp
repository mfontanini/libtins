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

#include "ip.h"
#include "rawpdu.h"
#include "constants.h"
#include "internals.h"
#include "ip_reassembler.h"

namespace Tins {
namespace Internals {
IPv4Stream::IPv4Stream() 
: received_end(false), received_size(), total_size() 
{ 

}

void IPv4Stream::add_fragment(IP *ip) {
    fragments_type::iterator it = fragments.begin();
    uint16_t offset = extract_offset(ip);
    while(it != fragments.end() && offset > it->offset()) {
        ++it;
    }
    // No duplicates plx
    if(it != fragments.end() && it->offset() == offset) 
        return;
    fragments.insert(it, IPv4Fragment(ip->inner_pdu(), offset));
    received_size += ip->inner_pdu()->size();
    if(!extract_more_frag(ip)) {
        total_size = offset + ip->inner_pdu()->size();
        received_end = true;
    }
    if(offset == 0)
        transport_proto = ip->protocol();
}

bool IPv4Stream::is_complete() const {
    return received_end && received_size == total_size;
}

PDU *IPv4Stream::allocate_pdu() const {
    PDU::serialization_type buffer;
    buffer.reserve(total_size);
    // Check if we actually have all the data we need. Otherwise return nullptr;
    uint16_t expected = 0;
    for(fragments_type::const_iterator it = fragments.begin(); it != fragments.end(); ++it) {
        if(expected != it->offset())
            return 0;
        expected = it->offset() + it->payload().size();
        buffer.insert(buffer.end(), it->payload().begin(), it->payload().end());
    }
    return Internals::pdu_from_flag(
        static_cast<Constants::IP::e>(transport_proto),
        &buffer[0],
        buffer.size()
    );
}

uint16_t IPv4Stream::extract_offset(const IP *ip) {
    return (ip->frag_off() & 0x1fff) * 8;
}

bool IPv4Stream::extract_more_frag(const IP *ip) {
    return ip->frag_off() & 0x2000;
}
} // namespace Internals

IPv4Reassembler::IPv4Reassembler(overlapping_technique technique)
: technique(technique)
{

}

IPv4Reassembler::packet_status IPv4Reassembler::process(PDU &pdu) {
    IP *ip = pdu.find_pdu<IP>();
    if(ip && ip->inner_pdu()) {
        // There's fragmentation
        if(ip->is_fragmented()) {
            // Create it or look it up, it's the same
            Internals::IPv4Stream &stream = streams[make_key(ip)];
            stream.add_fragment(ip);
            if(stream.is_complete()) {
                PDU *pdu = stream.allocate_pdu();
                // The packet is corrupt
                if(!pdu)  {
                    streams.erase(make_key(ip));
                    return FRAGMENTED;
                }
                ip->inner_pdu(pdu);
                ip->frag_off(0);
                return REASSEMBLED;
            }
            else
                return FRAGMENTED;
        }
    }
    return NOT_FRAGMENTED;
}

IPv4Reassembler::key_type IPv4Reassembler::make_key(const IP *ip) const {
    return std::make_pair(
        ip->id(),
        make_address_pair(ip->src_addr(), ip->dst_addr())
    );
}

IPv4Reassembler::address_pair IPv4Reassembler::make_address_pair(IPv4Address addr1, IPv4Address addr2) const {
    if(addr1 < addr2)
        return std::make_pair(addr1, addr2);
    else
        return std::make_pair(addr2, addr1);
}

void IPv4Reassembler::clear_streams() {
    streams.clear();
}

void IPv4Reassembler::remove_stream(uint16_t id, IPv4Address addr1, IPv4Address addr2) {
    streams.erase(
        std::make_pair(
            id, 
            make_address_pair(addr1, addr2)
        )
    );
}

} // namespace Tins
