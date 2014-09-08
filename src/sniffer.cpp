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

#ifdef WIN32
    #define TINS_PREFIX_INTERFACE(x) ("\\Device\\NPF_" + x)
#else // WIN32
    #define TINS_PREFIX_INTERFACE(x) (x)
#endif // WIN32

#include <algorithm>
#include <sstream>
#include "sniffer.h"
#include "dot11/dot11_base.h"
#include "ethernetII.h"
#include "radiotap.h"
#include "loopback.h"
#include "rawpdu.h"
#include "dot3.h"
#include "sll.h"
#include "ppi.h"

using std::string;
using std::runtime_error;

namespace Tins {
BaseSniffer::BaseSniffer() 
: handle(0), mask(0), extract_raw(false)
{
    
}
    
BaseSniffer::~BaseSniffer() 
{
    if (handle) {
        pcap_close(handle);
    }
}

void BaseSniffer::set_pcap_handle(pcap_t* const pcap_handle)
{
    handle = pcap_handle;
}

pcap_t* BaseSniffer::get_pcap_handle()
{
    return handle;
}

const pcap_t* BaseSniffer::get_pcap_handle() const
{
    return handle;
}

void BaseSniffer::set_if_mask(bpf_u_int32 if_mask)
{
    mask = if_mask;
}

bpf_u_int32 BaseSniffer::get_if_mask() const
{
    return mask;
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

#ifdef HAVE_DOT11
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
#endif

PtrPacket BaseSniffer::next_packet() {
    sniff_data data;
    const int iface_type = pcap_datalink(handle);
    pcap_handler handler = 0;
    if(extract_raw)
        handler = &sniff_loop_handler<RawPDU>;
    else if(iface_type == DLT_EN10MB)
        handler = sniff_loop_eth_handler;
    else if(iface_type == DLT_IEEE802_11_RADIO) {
        #ifdef HAVE_DOT11
            handler = &sniff_loop_handler<RadioTap>;
        #else
            throw protocol_disabled();
        #endif
    }
    else if(iface_type == DLT_IEEE802_11) {
        #ifdef HAVE_DOT11
            handler = sniff_loop_dot11_handler;
        #else
            throw protocol_disabled();
        #endif
    }
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

void BaseSniffer::set_extract_raw_pdus(bool value) {
    extract_raw = value;
}

void BaseSniffer::stop_sniff() {
    pcap_breakloop(handle);
}

int BaseSniffer::get_fd() {
    #ifndef WIN32
        return pcap_get_selectable_fd(handle);
    #else
        throw std::runtime_error("Method not supported in Windows platform");
    #endif // WIN32
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
    if(pcap_compile(handle, &prog, filter.c_str(), 0, mask) == -1) {
        return false;
    }
    bool result = pcap_setfilter(handle, &prog) != -1;
    pcap_freecode(&prog);
    return result;
}

void BaseSniffer::set_timeout(int ms) {
    pcap_set_timeout(handle, ms);
}

// ****************************** Sniffer ******************************

Sniffer::Sniffer(const string &device, const SnifferConfiguration& configuration)
{
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
        throw std::runtime_error(pcap_geterr(get_pcap_handle()));
    }

    // Configure the sniffer's attributes after activation.
    configuration.configure_sniffer_post_activation(*this);
}

Sniffer::Sniffer(const std::string &device, unsigned max_packet_size, bool promisc, 
                 const std::string &filter, bool rfmon)
{
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
        throw std::runtime_error(pcap_geterr(get_pcap_handle()));
    }

    // Configure the sniffer's attributes after activation.
    configuration.configure_sniffer_post_activation(*this);
}

Sniffer::Sniffer(const std::string &device, promisc_type promisc, const std::string &filter,
                 bool rfmon)
{
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
        throw std::runtime_error(pcap_geterr(get_pcap_handle()));
    }

    // Configure the sniffer's attributes after activation.
    configuration.configure_sniffer_post_activation(*this);
}

void Sniffer::set_snap_len(unsigned snap_len)
{
    if (pcap_set_snaplen(get_pcap_handle(), snap_len)) {
        throw std::runtime_error(pcap_geterr(get_pcap_handle()));
    }
}

void Sniffer::set_buffer_size(unsigned buffer_size)
{
    if (pcap_set_buffer_size(get_pcap_handle(), buffer_size)) {
        throw std::runtime_error(pcap_geterr(get_pcap_handle()));
    }
}

void Sniffer::set_promisc_mode(bool promisc_enabled)
{
    if (pcap_set_promisc(get_pcap_handle(), promisc_enabled)) {
        throw runtime_error(pcap_geterr(get_pcap_handle()));
    }
}

void Sniffer::set_rfmon(bool rfmon_enabled)
{
    #ifndef WIN32
    if (pcap_can_set_rfmon(get_pcap_handle()) == 1) {
        if (pcap_set_rfmon(get_pcap_handle(), rfmon_enabled)) {
            throw runtime_error(pcap_geterr(get_pcap_handle()));
        }
    }
    #endif
}


// **************************** FileSniffer ****************************

FileSniffer::FileSniffer(const string &file_name, const SnifferConfiguration& configuration) {
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *phandle = pcap_open_offline(file_name.c_str(), error);
    if(!phandle) {
        throw std::runtime_error(error);
    }
    set_pcap_handle(phandle);

    // Configure the sniffer
    configuration.configure_sniffer_pre_activation(*this);
    
}

FileSniffer::FileSniffer(const std::string &file_name, const std::string &filter)
{
    SnifferConfiguration config;
    config.set_filter(filter);

    char error[PCAP_ERRBUF_SIZE];
    pcap_t *phandle = pcap_open_offline(file_name.c_str(), error);
    if(!phandle) {
        throw std::runtime_error(error);
    }
    set_pcap_handle(phandle);

    // Configure the sniffer
    config.configure_sniffer_pre_activation(*this);
}

// ************************ SnifferConfiguration ************************

const unsigned SnifferConfiguration::DEFAULT_SNAP_LEN = 65535;
const unsigned SnifferConfiguration::DEFAULT_TIMEOUT = 1000;

SnifferConfiguration::SnifferConfiguration() :
    _snap_len(DEFAULT_SNAP_LEN),
    _has_buffer_size(false), _buffer_size(0),
    _has_promisc(false), _promisc(false),
    _has_rfmon(false), _rfmon(false),
    _has_filter(false),
    _timeout(DEFAULT_TIMEOUT)
{

}

void SnifferConfiguration::configure_sniffer_pre_activation(Sniffer& sniffer) const
{
    sniffer.set_snap_len(_snap_len);
    sniffer.set_timeout(_timeout);
    if (_has_buffer_size) {
        sniffer.set_buffer_size(_buffer_size);
    }
    if (_has_promisc) {
        sniffer.set_promisc_mode(_promisc);
    }
    if (_has_rfmon) {
        sniffer.set_rfmon(_rfmon);
    }
}

void SnifferConfiguration::configure_sniffer_pre_activation(FileSniffer& sniffer) const
{
    if (_has_filter) {
        if (!sniffer.set_filter(_filter)) {
            throw std::runtime_error("Could not set the filter!");
        }
    }
}

void SnifferConfiguration::configure_sniffer_post_activation(Sniffer& sniffer) const
{
    if (_has_filter) {
        if (!sniffer.set_filter(_filter)) {
            throw std::runtime_error("Could not set the filter! ");
        }
    }
}

void SnifferConfiguration::set_snap_len(unsigned snap_len)
{
    _snap_len = snap_len;
}

void SnifferConfiguration::set_buffer_size(unsigned buffer_size)
{
    _has_buffer_size = true;
    _buffer_size = buffer_size;
}

void SnifferConfiguration::set_promisc_mode(bool enabled)
{
    _has_promisc = true;
    _promisc = enabled;
}

void SnifferConfiguration::set_filter(const std::string& filter)
{
    _has_filter = true;
    _filter = filter;
}

void SnifferConfiguration::set_rfmon(bool enabled)
{
    _has_rfmon = true;
    _rfmon = enabled;
}

void SnifferConfiguration::set_timeout(unsigned timeout)
{
    _timeout = timeout;
}

}
