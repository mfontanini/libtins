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
}

Tins::Sniffer::~Sniffer() {
    if(handle)
        pcap_close(handle);
}

bool Tins::Sniffer::compile_set_filter(const string &filter, bpf_program &prog) {
    return (pcap_compile(handle, &prog, filter.c_str(), 0, ip) != -1 && pcap_setfilter(handle, &prog) != -1);
}

Tins::PDU *Tins::Sniffer::next_pdu(const string &filter) {
    bpf_program prog;
    if(!compile_set_filter(filter, prog))
        return 0;
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
    pcap_freecode(&prog);
    return ret;
}

void Tins::Sniffer::sniff_loop(const std::string &filter, AbstractSnifferHandler *cback_handler, uint32_t max_packets) {
    bpf_program prog;
    if(compile_set_filter(filter, prog)) {
        LoopData data(handle, cback_handler);
        pcap_loop(handle, max_packets, Sniffer::callback_handler, (u_char*)&data);
        pcap_freecode(&prog);
    }
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

