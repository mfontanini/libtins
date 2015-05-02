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
 
#ifndef _WIN32
    #include <sys/time.h>
#endif
#include <stdexcept>
#include "packet_writer.h"
#include "pdu.h"

namespace Tins {
PacketWriter::PacketWriter(const std::string &file_name, LinkType lt) {
    init(file_name, lt);
}

PacketWriter::~PacketWriter() {
    if(dumper && handle) {
        pcap_dump_close(dumper);
        pcap_close(handle);
    }
}

void PacketWriter::write(PDU &pdu) {
    PDU::serialization_type buffer = pdu.serialize();
    timeval tm;
    #ifndef _WIN32
        gettimeofday(&tm, 0);
    #else
        // fixme
        tm = timeval();
    #endif
    struct pcap_pkthdr header = { 
        tm,
        static_cast<bpf_u_int32>(buffer.size()),
        static_cast<bpf_u_int32>(buffer.size())
    };
    pcap_dump((u_char*)dumper, &header, &buffer[0]);
}

void PacketWriter::init(const std::string& file_name, int link_type) {
    handle = pcap_open_dead(link_type, 65535);
    if(!handle)
        throw std::runtime_error("Error creating pcap handle");
    dumper = pcap_dump_open(handle, file_name.c_str());
    if(!dumper) {
        // RAII plx
        pcap_close(handle);
        throw std::runtime_error(pcap_geterr(handle));
    }
}

}
