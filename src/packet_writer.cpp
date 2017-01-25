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
 
#ifndef _WIN32
    #include <sys/time.h>
#endif
#include <stdexcept>
#include <string.h>
#include "packet_writer.h"
#include "packet.h"
#include "pdu.h"
#include "exceptions.h"

using std::string;

namespace Tins {

PacketWriter::PacketWriter(const string& file_name, LinkType lt) {
    init(file_name, lt);
}

PacketWriter::~PacketWriter() {
    if (dumper_ && handle_) {
        pcap_dump_close(dumper_);
        pcap_close(handle_);
    }
}

void PacketWriter::write(PDU& pdu) {
    timeval tv;
    #ifndef _WIN32
        gettimeofday(&tv, 0);
    #else
        // fixme
        tv = timeval();
    #endif
    write(pdu, tv);
}

void PacketWriter::write(Packet& packet) {
    timeval tv;
    tv.tv_sec = packet.timestamp().seconds();
    tv.tv_usec = packet.timestamp().microseconds();
    write(*packet.pdu(), tv);
}

void PacketWriter::write(PDU& pdu, const struct timeval& tv) {
    PDU::serialization_type buffer = pdu.serialize();
    struct pcap_pkthdr header;
    memset(&header, 0, sizeof(header));
    header.ts = tv;
    header.caplen = static_cast<bpf_u_int32>(buffer.size());
    header.len = static_cast<bpf_u_int32>(buffer.size());
    pcap_dump((u_char*)dumper_, &header, &buffer[0]);
}

void PacketWriter::init(const string& file_name, int link_type) {
    handle_ = pcap_open_dead(link_type, 65535);
    if (!handle_) {
        throw pcap_open_failed();
    }
    dumper_ = pcap_dump_open(handle_, file_name.c_str());
    if (!dumper_) {
        pcap_close(handle_);
        throw pcap_error(pcap_geterr(handle_));
    }
}

} // Tins
