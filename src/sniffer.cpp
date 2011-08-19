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


#include <stdexcept>
#include "sniffer.h"
#include "ethernetII.h"


using namespace std;

/** \cond */

struct LoopData {
    pcap_t *handle;
    Tins::AbstractSnifferHandler *c_handler;
    
    LoopData(pcap_t *_handle, Tins::AbstractSnifferHandler *_handler) : handle(_handle), c_handler(_handler) { }
};

/** \endcond */


Tins::Sniffer::Sniffer(const string &device, unsigned max_packet_size) {
    char error[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(device.c_str(), &ip, &mask, error) == -1)
        throw runtime_error(error);
    handle = pcap_open_live(device.c_str(), max_packet_size, 0, 0, error);
    if(!handle)
        throw runtime_error(error);
    actual_filter.bf_insns = 0;
}

Tins::Sniffer::~Sniffer() {
    if(actual_filter.bf_insns)
        pcap_freecode(&actual_filter);
    if(handle)
        pcap_close(handle);
}

bool Tins::Sniffer::compile_set_filter(const string &filter, bpf_program &prog) {
    return (pcap_compile(handle, &prog, filter.c_str(), 0, ip) != -1 && pcap_setfilter(handle, &prog) != -1);
}

Tins::PDU *Tins::Sniffer::next_packet(const string &filter) {
    if(filter.size())
        set_filter(filter);
    pcap_pkthdr header;
    PDU *ret = 0;
    while(!ret) {
        const u_char *content = pcap_next(handle, &header);
        try {
            ret = new EthernetII((const uint8_t*)content, header.caplen);
        }
        catch(...) {
            ret = 0;
        }
    }
    return ret;
}

void Tins::Sniffer::stop_sniff() {
    pcap_breakloop(handle);
}

void Tins::Sniffer::sniff_loop(AbstractSnifferHandler *cback_handler, const string &filter, uint32_t max_packets) {
    if(filter.size())
        set_filter(filter);
    LoopData data(handle, cback_handler);
    pcap_loop(handle, max_packets, Sniffer::callback_handler, (u_char*)&data);
}

bool Tins::Sniffer::set_filter(const std::string &filter) {
    if(actual_filter.bf_insns)
        pcap_freecode(&actual_filter);
    return compile_set_filter(filter, actual_filter);
}

// Static
void Tins::Sniffer::callback_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    try {
        PDU *pdu = new EthernetII((const uint8_t*)packet, header->caplen);
        LoopData *data = reinterpret_cast<LoopData*>(args);
        bool ret_val = data->c_handler->handle(pdu);
        delete pdu;
        if(!ret_val)
            pcap_breakloop(data->handle);
    }
    catch(...) {
        
    }
}

