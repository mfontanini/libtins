/*
 * Copyright (c) 2012, Matias Fontanini
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

#include <algorithm>
#include "sniffer.h"


using std::string;
using std::runtime_error;

namespace Tins {
BaseSniffer::BaseSniffer() 
: handle(0), mask(0)
{
    
}
    
BaseSniffer::~BaseSniffer() {
    if(handle)
        pcap_close(handle);
}

void BaseSniffer::init(pcap_t *phandle, const std::string &filter, 
  bpf_u_int32 if_mask) 
{
    handle = phandle;
    mask = if_mask;
    
    if(!filter.empty() && !set_filter(filter))
        throw runtime_error("Invalid filter");
}

struct sniff_data {
    struct timeval tv;
    PDU *pdu;
    bool packet_processed;

    sniff_data() : pdu(0), packet_processed(true) { }
};

template<typename T>
T *safe_alloc(const u_char *bytes, bpf_u_int32 len) {
    try {
        return new T((const uint8_t*)bytes, len);
    }
    catch(malformed_packet&) {
        return 0;
    }
}

template<typename T>
void sniff_loop_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    sniff_data *data = (sniff_data*)user;
    data->packet_processed = true;
    data->tv = h->ts;
    data->pdu = safe_alloc<T>(bytes, h->caplen);
}

void sniff_loop_eth_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    sniff_data *data = (sniff_data*)user;
    data->packet_processed = true;
    data->tv = h->ts;
    if(Internals::is_dot3((const uint8_t*)bytes, h->caplen))
        data->pdu = safe_alloc<Dot3>((const uint8_t*)bytes, h->caplen);
    else
        data->pdu = safe_alloc<EthernetII>((const uint8_t*)bytes, h->caplen);
}

void sniff_loop_dot11_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    sniff_data *data = (sniff_data*)user;
    data->packet_processed = true;
    data->tv = h->ts;
    try {
        data->pdu = Dot11::from_bytes(bytes, h->caplen);
    }
    catch(malformed_packet&) {
        
    }
}

PtrPacket BaseSniffer::next_packet() {
    sniff_data data;
    const int iface_type = pcap_datalink(handle);
    pcap_handler handler = 0;
    if(iface_type == DLT_EN10MB)
        handler = sniff_loop_eth_handler;
    else if(iface_type == DLT_IEEE802_11_RADIO)
        handler = &sniff_loop_handler<RadioTap>;
    else if(iface_type == DLT_IEEE802_11)
        handler = sniff_loop_dot11_handler;
    else if(iface_type == DLT_LOOP)
        handler = &sniff_loop_handler<Tins::Loopback>;
    else if(iface_type == DLT_LINUX_SLL)
        handler = &sniff_loop_handler<SLL>;
    else if(iface_type == DLT_PPI)
        handler = &sniff_loop_handler<PPI>;
    else
        throw unknown_link_type();
    // keep calling pcap_loop until a well-formed packet is found.
    while(data.pdu == 0 && data.packet_processed) {
        data.packet_processed = false;
        if(pcap_loop(handle, 1, handler, (u_char*)&data) < 0)
            return PtrPacket(0, Timestamp());
    }
    return PtrPacket(data.pdu, data.tv);
}

void BaseSniffer::stop_sniff() {
    pcap_breakloop(handle);
}

int BaseSniffer::get_fd() {
    return pcap_get_selectable_fd(handle);
}

int BaseSniffer::link_type() const {
    return pcap_datalink(handle);
}

BaseSniffer::iterator BaseSniffer::begin() {
    return iterator(this);
}

BaseSniffer::iterator BaseSniffer::end() {
    return iterator(0);
}

bool BaseSniffer::set_filter(const std::string &filter) {
    bpf_program prog;
    if(pcap_compile(handle, &prog, filter.c_str(), 0, mask) == -1)
        return false;
    bool result = pcap_setfilter(handle, &prog) != -1;
    pcap_freecode(&prog);
    return result;
}

// ****************************** Sniffer ******************************

Sniffer::Sniffer(const string &device, unsigned max_packet_size, 
  bool promisc, const string &filter)
{
    char error[PCAP_ERRBUF_SIZE];
    bpf_u_int32 ip, if_mask;
    if (pcap_lookupnet(device.c_str(), &ip, &if_mask, error) == -1) {
        ip = 0;
        if_mask = 0;
    }
    pcap_t *phandle = pcap_open_live(device.c_str(), max_packet_size, promisc, 0, error);
    if(!phandle)
        throw runtime_error(error);
    
    init(phandle, filter, if_mask);
}

// **************************** FileSniffer ****************************

FileSniffer::FileSniffer(const string &file_name, const string &filter) {
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *phandle = pcap_open_offline(file_name.c_str(), error);
    if(!phandle)
        throw std::runtime_error(error);
    
    init(phandle, filter, 0);
}
}
