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


using std::string;
using std::runtime_error;

namespace Tins {
BaseSniffer::BaseSniffer() : handle(0), mask(0)
{
    actual_filter.bf_insns = 0;
}
    
BaseSniffer::~BaseSniffer() {
    if(actual_filter.bf_insns)
        pcap_freecode(&actual_filter);
    if(handle)
        pcap_close(handle);
}

void BaseSniffer::init(pcap_t *phandle, const std::string &filter, 
  bpf_u_int32 if_mask) 
{
    handle = phandle;
    mask = if_mask;
    
    iface_type = pcap_datalink(handle);
    actual_filter.bf_insns = 0;
    if(!filter.empty() && !set_filter(filter))
        throw runtime_error("Invalid filter");
}

bool BaseSniffer::compile_set_filter(const string &filter, bpf_program &prog) {
    return (pcap_compile(handle, &prog, filter.c_str(), 0, mask) != -1 && pcap_setfilter(handle, &prog) != -1);
}

PDU *BaseSniffer::next_packet() {
    pcap_pkthdr header;
    PDU *ret = 0;
    while(!ret) {
        const u_char *content = pcap_next(handle, &header);
        if(content) {
            try {
                if(iface_type == DLT_EN10MB)
                    ret = new EthernetII((const uint8_t*)content, header.caplen);
                else if(iface_type == DLT_IEEE802_11_RADIO)
                    ret = new RadioTap((const uint8_t*)content, header.caplen);
                else if(iface_type == DLT_LOOP)
                    ret = new Tins::Loopback((const uint8_t*)content, header.caplen);
            }
            catch(...) {
                ret = 0;
            }
        }
    }
    return ret;
}

void BaseSniffer::stop_sniff() {
    pcap_breakloop(handle);
}

bool BaseSniffer::set_filter(const std::string &filter) {
    if(actual_filter.bf_insns)
        pcap_freecode(&actual_filter);
    return compile_set_filter(filter, actual_filter);
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
