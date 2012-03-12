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


#include "sniffer.h"
#include "ethernetII.h"
#include "radiotap.h"


using namespace std;

/** \cond */

struct LoopData {
    pcap_t *handle;
    Tins::AbstractSnifferHandler *c_handler;
    bool wired;
    
    LoopData(pcap_t *_handle, Tins::AbstractSnifferHandler *_handler, bool is_wired) : handle(_handle), c_handler(_handler), wired(is_wired) { }
};

/** \endcond */


Tins::Sniffer::Sniffer(const string &device, unsigned max_packet_size, unsigned timeout, const string &filter) throw(std::runtime_error) {
    char error[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(device.c_str(), &ip, &mask, error) == -1) {
        ip = 0;
        mask = 0;
    }
    handle = pcap_open_live(device.c_str(), max_packet_size, 0, timeout, error);
    if(!handle)
        throw runtime_error(error);
    wired = (pcap_datalink (handle) != DLT_IEEE802_11_RADIO); //better plx
    actual_filter.bf_insns = 0;
    if(filter.size() && !set_filter(filter))
        throw runtime_error("Invalid filter");
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

Tins::PDU *Tins::Sniffer::next_packet() {
    pcap_pkthdr header;
    PDU *ret = 0;
    while(!ret) {
        const u_char *content = pcap_next(handle, &header);
        if(content) {
            try {
                if(wired)
                    ret = new EthernetII((const uint8_t*)content, header.caplen);
                else
                    ret = new RadioTap((const uint8_t*)content, header.caplen);
            }
            catch(...) {
                ret = 0;
            }
        }
    }
    return ret;
}

void Tins::Sniffer::stop_sniff() {
    pcap_breakloop(handle);
}

void Tins::Sniffer::sniff_loop(AbstractSnifferHandler *cback_handler, uint32_t max_packets) {
    LoopData data(handle, cback_handler, wired);
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
        PDU *pdu = 0;
        LoopData *data = reinterpret_cast<LoopData*>(args);
        if(data->wired)
            pdu = new EthernetII((const uint8_t*)packet, header->caplen);
        else
            pdu = new RadioTap((const uint8_t*)packet, header->caplen);
        bool ret_val = data->c_handler->handle(pdu);
        delete pdu;
        if(!ret_val)
            pcap_breakloop(data->handle);
    }
    catch(...) {
        
    }
}

