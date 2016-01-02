/*
 * Copyright (c) 2015, Matias Fontanini
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

#include <iostream>
#include <stdexcept>
#include <string>
#include <functional>
#include <tins/tins.h>

using std::cout;
using std::endl;
using std::bind;
using std::string;
using std::runtime_error;
using std::exception;

using namespace Tins;

// This class captured packets on an interface, using the specified filter
// and will respond with ICMP error packets whenever a packet is captured.
// The response mechanism is pretty naive as it generates a packet which
// has swapped HW and IP addresses (dst as src, src as dst).
class ICMPResponder {
public:
    // Use the given interface and ICMP type/code on responses
    ICMPResponder(string iface, int type, int code) 
    : m_iface(iface), m_sender(iface), m_type(type), m_code(code) {

    }

    // Run using the given filter
    void run(const string& filter) {
        // Initialize the configuration
        SnifferConfiguration config;
        // Use promiscuous mode
        config.set_promisc_mode(true);
        // Use this packet filter
        config.set_filter(filter);
        // Use immediate mode (we don't want to buffer packets, we want the mright away).
        config.set_immediate_mode(true);

        // Now create the Sniffer
        Sniffer sniffer(m_iface, config);
        if (sniffer.link_type() != DLT_EN10MB) {
            throw runtime_error("Ethernet interfaces only supported");
        }
        // Start the sniffing! For each packet, ICMPReponder::callback will be called
        sniffer.sniff_loop(bind(&ICMPResponder::callback, this, std::placeholders::_1));
    }
private:
    // Extracts the payload to be used over the ICMP layer in the response.
    // This will be the entire IP header + 8 bytes of the next header.
    RawPDU extract_icmp_payload(IP& pdu) {
        PDU::serialization_type buffer = pdu.serialize();
        // Use whole IP + 8 bytes of next header.
        size_t end_index = pdu.header_size() + 8;
        return RawPDU(buffer.begin(), buffer.begin() + end_index);
    }

    // Generates an ICMP response given a packet.
    EthernetII generate_response(PDU& pdu) {
        // Find Ethernet and IP headers.
        EthernetII& received_eth = pdu.rfind_pdu<EthernetII>();
        IP& received_ip = pdu.rfind_pdu<IP>();

        // Create an Ethernet response, flipping the addresses
        EthernetII output(received_eth.src_addr(), received_eth.dst_addr());
        // Append an IP PDU, again flipping addresses.
        //output /= IP(received_ip.src_addr(), received_ip.dst_addr());
        output /= IP(received_ip.src_addr(), "8.8.8.8");

        // Now generate the ICMP layer using the type and code provided.
        ICMP icmp;
        icmp.type(static_cast<ICMP::Flags>(m_type));
        icmp.code(m_code);
        // Append the ICMP layer to our packet
        output /= icmp;
        // Extract the payload to be used over ICMP.
        output /= extract_icmp_payload(received_ip);
        return output;
    }

    // Packet capture callback
    bool callback(PDU& pdu) {
        // Generate a response for this packet
        EthernetII response = generate_response(pdu);
        // Send this packet!
        m_sender.send(response);
        return true;
    }

    string m_iface;
    PacketSender m_sender;
    int m_type;
    int m_code;
};

int main(int argc, char* argv[]) {
    const int type = 3;
    const int code = 0;
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " <interface> <pcap_filter>" << endl;
        return 1;
    }
    string iface = argv[1];
    string filter = argv[2];
    try {
        ICMPResponder responder(iface, type, code);
        responder.run(filter);
    }
    catch (exception& ex) {
        cout << "Error: " << ex.what() << endl;
    }
}