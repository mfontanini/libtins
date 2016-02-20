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

#include <iostream>
#include <string>
#include <functional>
#include <tins/tins.h>

using std::string;
using std::bind;
using std::cout;
using std::endl;
using std::exception;

using namespace Tins;

// This example will capture TCP packets and send packet that will reset
// the connection when it captures a packet with the SYN and ACK flags on.
class tcp_connection_closer {
public:
    tcp_connection_closer() {

    }

    void run(const string& interface) {
        using std::placeholders::_1;
        // Make the PacketSender use this interface by default
        sender_.default_interface(interface);

        // Create the sniffer configuration
        SnifferConfiguration config;
        config.set_filter("tcp");
        // We want to get the packets as fast as possible
        config.set_immediate_mode(true);
        // Create the sniffer and start the capture
        Sniffer sniffer(interface, config);
        sniffer.sniff_loop(bind(&tcp_connection_closer::callback, this, _1));
    }
private:
    bool callback(const PDU& pdu) {
        const EthernetII& eth = pdu.rfind_pdu<EthernetII>();
        const IP& ip = pdu.rfind_pdu<IP>();
        const TCP& tcp = pdu.rfind_pdu<TCP>();
        // We'll only close a connection when seeing a SYN|ACK
        if (tcp.flags() == (TCP::SYN | TCP::ACK)) {
            // Create an ethernet header flipping the addresses
            EthernetII packet(eth.src_addr(), eth.dst_addr());
            // Do the same for IP
            packet /= IP(ip.src_addr(), ip.dst_addr());
            // Flip TCP ports
            TCP response_tcp(tcp.sport(), tcp.dport());
            // Set RST|ACK flags
            response_tcp.flags(TCP::RST | TCP::ACK);
            // Use the right sequence and ack numbers
            response_tcp.seq(tcp.ack_seq());
            response_tcp.ack_seq(tcp.seq());
            // Add this PDU to the packet we'll send
            packet /= response_tcp;
            // Send it!
            sender_.send(packet);
        }
        return true;
    }

    PacketSender sender_;
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << *argv << " <interface>" << endl;
        return 1;
    }
    try {
        tcp_connection_closer closer;
        closer.run(argv[1]);
    }
    catch (exception& ex) {
        cout << "[-] Error: " << ex.what() << endl;
        return 1;
    }
}