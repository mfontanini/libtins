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

#ifdef _WIN32
    #define TINS_PREFIX_INTERFACE(x) ("\\Device\\NPF_" + x)
#else // _WIN32
    #define TINS_PREFIX_INTERFACE(x) (x)
#endif // _WIN32

#include <algorithm>
#include <sstream>
#include "sniffer.h"
#include "dot11/dot11_base.h"
#include "ethernetII.h"
#include "radiotap.h"
#include "loopback.h"
#include "rawpdu.h"
#include "dot3.h"
#include "pktap.h"
#include "sll.h"
#include "ppi.h"

using std::string;
using std::runtime_error;

namespace Tins {

BaseSniffer::BaseSniffer() 
: handle_(0), mask_(0), extract_raw_(false) {
    
}
    
BaseSniffer::~BaseSniffer() {
    if (handle_) {
        pcap_close(handle_);
    }
}

void BaseSniffer::set_pcap_handle(pcap_t* pcap_handle) {
    handle_ = pcap_handle;
}

pcap_t* BaseSniffer::get_pcap_handle() {
    return handle_;
}

const pcap_t* BaseSniffer::get_pcap_handle() const {
    return handle_;
}

void BaseSniffer::set_if_mask(bpf_u_int32 if_mask) {
    mask_ = if_mask;
}

bpf_u_int32 BaseSniffer::get_if_mask() const {
    return mask_;
}

struct sniff_data {
    struct timeval tv;
    PDU* pdu;
    bool packet_processed;

sniff_data() : tv(), pdu(0), packet_processed(true) { }
};

template<typename T>
T* safe_alloc(const u_char* bytes, bpf_u_int32 len) {
    try {
        return new T((const uint8_t*)bytes, len);
    }
    catch (malformed_packet&) {
        return 0;
    }
}

template<typename T>
void sniff_loop_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    sniff_data* data = (sniff_data*)user;
    data->packet_processed = true;
    data->tv = h->ts;
    data->pdu = safe_alloc<T>(bytes, h->caplen);
}

void sniff_loop_eth_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    sniff_data* data = (sniff_data*)user;
    data->packet_processed = true;
    data->tv = h->ts;
    if (Internals::is_dot3((const uint8_t*)bytes, h->caplen)) {
        data->pdu = safe_alloc<Dot3>((const uint8_t*)bytes, h->caplen);
    }
    else {
        data->pdu = safe_alloc<EthernetII>((const uint8_t*)bytes, h->caplen);
    }
}

#ifdef TINS_HAVE_DOT11
void sniff_loop_dot11_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    sniff_data* data = (sniff_data*)user;
    data->packet_processed = true;
    data->tv = h->ts;
    try {
        data->pdu = Dot11::from_bytes(bytes, h->caplen);
    }
    catch(malformed_packet&) {
        
    }
}
#endif

PtrPacket BaseSniffer::next_packet() {
    sniff_data data;
    const int iface_type = pcap_datalink(handle_);
    pcap_handler handler = 0;
    if (extract_raw_) {
        handler = &sniff_loop_handler<RawPDU>;
    }
    else if (iface_type == DLT_EN10MB) {
        handler = sniff_loop_eth_handler;
    }
    else if (iface_type == DLT_IEEE802_11_RADIO) {
        #ifdef TINS_HAVE_DOT11
            handler = &sniff_loop_handler<RadioTap>;
        #else
            throw protocol_disabled();
        #endif
    }
    else if (iface_type == DLT_IEEE802_11) {
        #ifdef TINS_HAVE_DOT11
            handler = sniff_loop_dot11_handler;
        #else
            throw protocol_disabled();
        #endif
    }
    #ifdef DLT_PKTAP
    else if (iface_type == DLT_PKTAP) {
        handler = &sniff_loop_handler<PKTAP>;
    }
    #endif // DLT_PKTAP
    else if (iface_type == DLT_NULL) {
        handler = &sniff_loop_handler<Tins::Loopback>;
    }
    else if (iface_type == DLT_LINUX_SLL) {
        handler = &sniff_loop_handler<SLL>;
    }
    else if (iface_type == DLT_PPI) {
        handler = &sniff_loop_handler<PPI>;
    }
    else {
        throw unknown_link_type();
    }
    // keep calling pcap_loop until a well-formed packet is found.
    while (data.pdu == 0 && data.packet_processed) {
        data.packet_processed = false;
        if (pcap_loop(handle_, 1, handler, (u_char*)&data) < 0) {
            return PtrPacket(0, Timestamp());
        }
    }
    return PtrPacket(data.pdu, data.tv);
}

void BaseSniffer::set_extract_raw_pdus(bool value) {
    extract_raw_ = value;
}

void BaseSniffer::stop_sniff() {
    pcap_breakloop(handle_);
}

int BaseSniffer::get_fd() {
    #ifndef _WIN32
        return pcap_get_selectable_fd(handle_);
    #else
        throw unsupported_function();
    #endif // _WIN32
}

int BaseSniffer::link_type() const {
    return pcap_datalink(handle_);
}

BaseSniffer::iterator BaseSniffer::begin() {
    return iterator(this);
}

BaseSniffer::iterator BaseSniffer::end() {
    return iterator(0);
}

bool BaseSniffer::set_filter(const string& filter) {
    bpf_program prog;
    if (pcap_compile(handle_, &prog, filter.c_str(), 0, mask_) == -1) {
        return false;
    }
    bool result = pcap_setfilter(handle_, &prog) != -1;
    pcap_freecode(&prog);
    return result;
}

void BaseSniffer::set_timeout(int ms) {
    pcap_set_timeout(handle_, ms);
}

bool BaseSniffer::set_direction(pcap_direction_t d) {
	bool result = pcap_setdirection(handle_, d) != -1;
	return result;
}

// ****************************** Sniffer ******************************

Sniffer::Sniffer(const string& device, const SnifferConfiguration& configuration) {
    char error[PCAP_ERRBUF_SIZE];
    pcap_t* phandle = pcap_create(TINS_PREFIX_INTERFACE(device).c_str(), error);
    if (!phandle) {
        throw runtime_error(error);
    }
    set_pcap_handle(phandle);

    // Set the netmask if we are able to find it.
    bpf_u_int32 ip, if_mask;
    if (pcap_lookupnet(TINS_PREFIX_INTERFACE(device).c_str(), &ip, &if_mask, error) == 0) {
        set_if_mask(if_mask);
    }

    // Configure the sniffer's attributes prior to activation.
    configuration.configure_sniffer_pre_activation(*this);

    // Finally, activate the pcap. In case of error throw runtime_error
    if (pcap_activate(get_pcap_handle()) < 0) {
        throw pcap_error(pcap_geterr(get_pcap_handle()));
    }

    // Configure the sniffer's attributes after activation.
    configuration.configure_sniffer_post_activation(*this);
}

Sniffer::Sniffer(const string& device,
                 unsigned max_packet_size,
                 bool promisc, 
                 const string& filter,
                 bool rfmon) {
    SnifferConfiguration configuration;
    configuration.set_snap_len(max_packet_size);
    configuration.set_promisc_mode(promisc);
    configuration.set_filter(filter);
    configuration.set_rfmon(rfmon);

    char error[PCAP_ERRBUF_SIZE];
    pcap_t* phandle = pcap_create(TINS_PREFIX_INTERFACE(device).c_str(), error);
    if (!phandle) {
        throw runtime_error(error);
    }
    set_pcap_handle(phandle);

    // Set the netmask if we are able to find it.
    bpf_u_int32 ip, if_mask;
    if (pcap_lookupnet(TINS_PREFIX_INTERFACE(device).c_str(), &ip, &if_mask, error) == 0) {
        set_if_mask(if_mask);
    }

    // Configure the sniffer's attributes prior to activation.
    configuration.configure_sniffer_pre_activation(*this);

    // Finally, activate the pcap. In case of error throw runtime_error
    if (pcap_activate(get_pcap_handle()) < 0) {
        throw pcap_error(pcap_geterr(get_pcap_handle()));
    }

    // Configure the sniffer's attributes after activation.
    configuration.configure_sniffer_post_activation(*this);
}

Sniffer::Sniffer(const string& device, 
                 promisc_type promisc,
                 const string& filter,
                 bool rfmon) {
    SnifferConfiguration configuration;
    configuration.set_promisc_mode(promisc == PROMISC);
    configuration.set_filter(filter);
    configuration.set_rfmon(rfmon);

    char error[PCAP_ERRBUF_SIZE];
    pcap_t* phandle = pcap_create(TINS_PREFIX_INTERFACE(device).c_str(), error);
    if (!phandle) {
        throw runtime_error(error);
    }
    set_pcap_handle(phandle);

    // Set the netmask if we are able to find it.
    bpf_u_int32 ip, if_mask;
    if (pcap_lookupnet(TINS_PREFIX_INTERFACE(device).c_str(), &ip, &if_mask, error) == 0) {
        set_if_mask(if_mask);
    }

    // Configure the sniffer's attributes prior to activation.
    configuration.configure_sniffer_pre_activation(*this);

    // Finally, activate the pcap. In case of error throw runtime_error
    if (pcap_activate(get_pcap_handle()) < 0) {
        throw pcap_error(pcap_geterr(get_pcap_handle()));
    }

    // Configure the sniffer's attributes after activation.
    configuration.configure_sniffer_post_activation(*this);
}

void Sniffer::set_snap_len(unsigned snap_len) {
    if (pcap_set_snaplen(get_pcap_handle(), snap_len)) {
        throw pcap_error(pcap_geterr(get_pcap_handle()));
    }
}

void Sniffer::set_buffer_size(unsigned buffer_size) {
    if (pcap_set_buffer_size(get_pcap_handle(), buffer_size)) {
        throw pcap_error(pcap_geterr(get_pcap_handle()));
    }
}

void Sniffer::set_promisc_mode(bool promisc_enabled) {
    if (pcap_set_promisc(get_pcap_handle(), promisc_enabled)) {
        throw pcap_error(pcap_geterr(get_pcap_handle()));
    }
}

void Sniffer::set_immediate_mode(bool enabled) {
    // As of libpcap version 1.5.0 this function exists. Before, it was
    // technically always immediate mode since capture used TPACKET_V1/2
    // which doesn't do packet buffering.
    #ifdef HAVE_PCAP_IMMEDIATE_MODE
    if (pcap_set_immediate_mode(get_pcap_handle(), enabled)) {
        throw pcap_error(pcap_geterr(get_pcap_handle()));
    }
    #endif // HAVE_PCAP_IMMEDIATE_MODE
}

void Sniffer::set_timestamp_precision(int value) {
    // This function exists as of libpcap version 1.5.0.
    #ifdef HAVE_PCAP_TIMESTAMP_PRECISION
    int result = pcap_set_tstamp_precision(get_pcap_handle(), value);
    if (result == PCAP_ERROR_TSTAMP_PRECISION_NOTSUP) {
        throw pcap_error("Timestamp precision not supported");
    }
    #endif // HAVE_PCAP_TIMESTAMP_PRECISION
}

void Sniffer::set_rfmon(bool rfmon_enabled) {
    #ifndef _WIN32
    if (pcap_can_set_rfmon(get_pcap_handle()) == 1) {
        if (pcap_set_rfmon(get_pcap_handle(), rfmon_enabled)) {
            throw pcap_error(pcap_geterr(get_pcap_handle()));
        }
    }
    #endif
}


// **************************** FileSniffer ****************************

FileSniffer::FileSniffer(const string& file_name, 
                         const SnifferConfiguration& configuration) {
    char error[PCAP_ERRBUF_SIZE];
    pcap_t* phandle = pcap_open_offline(file_name.c_str(), error);
    if (!phandle) {
        throw pcap_error(error);
    }
    set_pcap_handle(phandle);

    // Configure the sniffer
    configuration.configure_sniffer_pre_activation(*this);
    
}

FileSniffer::FileSniffer(const string& file_name, const string& filter) {
    SnifferConfiguration config;
    config.set_filter(filter);

    char error[PCAP_ERRBUF_SIZE];
    pcap_t* phandle = pcap_open_offline(file_name.c_str(), error);
    if (!phandle) {
        throw pcap_error(error);
    }
    set_pcap_handle(phandle);

    // Configure the sniffer
    config.configure_sniffer_pre_activation(*this);
}

// ************************ SnifferConfiguration ************************

const unsigned SnifferConfiguration::DEFAULT_SNAP_LEN = 65535;
const unsigned SnifferConfiguration::DEFAULT_TIMEOUT = 1000;

SnifferConfiguration::SnifferConfiguration()
: flags_(0), snap_len_(DEFAULT_SNAP_LEN), buffer_size_(0), timeout_(DEFAULT_TIMEOUT),
  promisc_(false), rfmon_(false), immediate_mode_(false), direction_(PCAP_D_INOUT),
  timestamp_precision_(0) {

}

void SnifferConfiguration::configure_sniffer_pre_activation(Sniffer& sniffer) const {
    sniffer.set_snap_len(snap_len_);
    sniffer.set_timeout(timeout_);
    if ((flags_ & BUFFER_SIZE) != 0) {
        sniffer.set_buffer_size(buffer_size_);
    }
    if ((flags_ & PROMISCUOUS) != 0) {
        sniffer.set_promisc_mode(promisc_);
    }
    if ((flags_ & RFMON) != 0) {
        sniffer.set_rfmon(rfmon_);
    }
    if ((flags_ & IMMEDIATE_MODE) != 0) {
        sniffer.set_immediate_mode(immediate_mode_);
    }
    if ((flags_ & TIMESTAMP_PRECISION) != 0) {
        sniffer.set_timestamp_precision(timestamp_precision_);
    }
}

void SnifferConfiguration::configure_sniffer_pre_activation(FileSniffer& sniffer) const {
    if ((flags_ & PACKET_FILTER) != 0) {
        if (!sniffer.set_filter(filter_)) {
            throw invalid_pcap_filter(pcap_geterr(sniffer.get_pcap_handle()));
        }
    }
}

void SnifferConfiguration::configure_sniffer_post_activation(Sniffer& sniffer) const {
    if ((flags_ & PACKET_FILTER) != 0) {
        if (!sniffer.set_filter(filter_)) {
            throw invalid_pcap_filter(pcap_geterr(sniffer.get_pcap_handle()));
        }
    }
    // TODO: see how to actually do this on winpcap
    #ifndef _WIN32
    if ((flags_ & DIRECTION) != 0) {
        if (!sniffer.set_direction(direction_)) {
            throw pcap_error(pcap_geterr(sniffer.get_pcap_handle()));
        }
    }
    #endif // _WIN32
}

void SnifferConfiguration::set_snap_len(unsigned snap_len) {
    snap_len_ = snap_len;
}

void SnifferConfiguration::set_buffer_size(unsigned buffer_size) {
    flags_ |= BUFFER_SIZE;
    buffer_size_ = buffer_size;
}

void SnifferConfiguration::set_promisc_mode(bool enabled) {
    flags_ |= PROMISCUOUS;
    promisc_ = enabled;
}

void SnifferConfiguration::set_filter(const string& filter) {
    flags_ |= PACKET_FILTER;
    filter_ = filter;
}

void SnifferConfiguration::set_rfmon(bool enabled) {
    flags_ |= RFMON;
    rfmon_ = enabled;
}

void SnifferConfiguration::set_timeout(unsigned timeout) {
    timeout_ = timeout;
}

void SnifferConfiguration::set_immediate_mode(bool enabled) {
    flags_ |= IMMEDIATE_MODE;
    immediate_mode_ = enabled;
}

void SnifferConfiguration::set_timestamp_precision(int value) {
    flags_ |= TIMESTAMP_PRECISION;
    timestamp_precision_ = value;
}

void SnifferConfiguration::set_direction(pcap_direction_t direction) {
    direction_ =  direction;
    flags_ |= DIRECTION;
}

} // Tins
