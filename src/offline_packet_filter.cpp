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

#include <stdexcept>
#include "offline_packet_filter.h"
#include "pdu.h"

namespace Tins {

OfflinePacketFilter::OfflinePacketFilter(const OfflinePacketFilter& other)
{
    *this = other;
}

OfflinePacketFilter& OfflinePacketFilter::operator=(const OfflinePacketFilter& other)
{
    string_filter = other.string_filter;
    init(string_filter, pcap_datalink(other.handle), pcap_snapshot(other.handle));
    return *this;
}

OfflinePacketFilter::~OfflinePacketFilter()
{
    pcap_freecode(&filter);
    pcap_close(handle);
}

void OfflinePacketFilter::init(const std::string& pcap_filter, int link_type, 
    unsigned int snap_len) 
{
    handle = pcap_open_dead(
        link_type,
        snap_len
    );
    if(pcap_compile(handle, &filter, pcap_filter.c_str(), 1, 0xffffffff) == -1)
    {
        throw std::runtime_error(pcap_geterr(handle));
    }
}

bool OfflinePacketFilter::matches_filter(const uint8_t* buffer, 
    uint32_t total_sz) const
{
    pcap_pkthdr header = {};
    header.len = total_sz;
    header.caplen = total_sz;
    return pcap_offline_filter(
        &filter,
        &header,
        buffer
    );
}

bool OfflinePacketFilter::matches_filter(PDU& pdu) const
{
    PDU::serialization_type buffer = pdu.serialize();
    return matches_filter(&buffer[0], buffer.size());
}

} // Tins
