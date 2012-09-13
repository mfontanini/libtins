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
 
#ifndef WIN32
    #include <sys/time.h>
#endif
#include <stdexcept>
#include "packet_writer.h"
#include "pdu.h"

namespace Tins {
PacketWriter::PacketWriter(const std::string &file_name, LinkType lt) {
    handle = pcap_open_dead(lt, 65535);
    if(!handle)
        throw std::runtime_error("Error creating pcap handle");
    dumper = pcap_dump_open(handle, file_name.c_str());
    if(!dumper) {
        // RAII plx
        pcap_close(handle);
        throw std::runtime_error(pcap_geterr(handle));
    }
}

PacketWriter::~PacketWriter() {
    pcap_dump_close(dumper);
    pcap_close(handle);
}

void PacketWriter::write(PDU &pdu) {
    PDU::serialization_type buffer = pdu.serialize();
    struct timeval tm;
    gettimeofday(&tm, 0);
    struct pcap_pkthdr header = { 
        tm,
        buffer.size(),
        buffer.size()
    };
    pcap_dump((u_char*)dumper, &header, &buffer[0]);
}
}
