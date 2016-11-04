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

#include <tins/tins.h>
#include <iostream>

using std::cout;
using std::endl;

using namespace Tins;

PacketSender sender;

bool callback(const PDU& pdu) {
    // The packet probably looks like this:
    //
    // EthernetII / IP / UDP / RawPDU
    //
    // So we retrieve each layer, and construct a 
    // DNS PDU from the RawPDU layer contents.
    EthernetII eth = pdu.rfind_pdu<EthernetII>();
    IP ip = eth.rfind_pdu<IP>();
    UDP udp = ip.rfind_pdu<UDP>();
    DNS dns = udp.rfind_pdu<RawPDU>().to<DNS>();

    // Is it a DNS query?
    if (dns.type() == DNS::QUERY) {
        // Let's see if there's any query for an "A" record.
        for (const auto& query : dns.queries()) {
            if (query.query_type() == DNS::A) {
                // Here's one! Let's add an answer.
                dns.add_answer(
                    DNS::resource(
                        query.dname(), 
                        "127.0.0.1",
                        DNS::A, 
                        query.query_class(), 
                        // 777 is just a random TTL
                        777
                    )
                );
            }
        }
        // Have we added some answers?
        if (dns.answers_count() > 0) {
            // It's a response now
            dns.type(DNS::RESPONSE);
            // Recursion is available(just in case)
            dns.recursion_available(1);
            // Build our packet
            auto pkt = EthernetII(eth.src_addr(), eth.dst_addr()) /
                       IP(ip.src_addr(), ip.dst_addr()) /
                       UDP(udp.sport(), udp.dport()) /
                       dns;
            // Send it!
            sender.send(pkt);
        }
    }
    return true;
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        cout << "Usage: " <<* argv << " <interface>" << endl;
        return 1;
    }
    // Sniff on the provided interface in promiscuos mode
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    // Use immediate mode so we get the packets as fast as we can
    config.set_immediate_mode(true);
    // Only capture udp packets sent to port 53
    config.set_filter("udp and dst port 53");
    Sniffer sniffer(argv[1], config);
    
    // All packets will be sent through the provided interface
    sender.default_interface(argv[1]);
    
    // Start the capture
    sniffer.sniff_loop(callback);
}
