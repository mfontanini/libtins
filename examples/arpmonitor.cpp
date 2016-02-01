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
#include <map>
#include <iostream>
#include <functional>

using std::cout;
using std::endl;
using std::map;
using std::bind;

using namespace Tins;

class arp_monitor {
public:
    void run(Sniffer& sniffer);
private:
    bool callback(const PDU& pdu);

    map<IPv4Address, HWAddress<6>> addresses;
};

void arp_monitor::run(Sniffer& sniffer) {
    sniffer.sniff_loop(
        bind(
            &arp_monitor::callback,
            this,
            std::placeholders::_1
        )
    );
}

bool arp_monitor::callback(const PDU& pdu) {
    // Retrieve the ARP layer
    const ARP& arp = pdu.rfind_pdu<ARP>();
    // Is it an ARP reply?
    if (arp.opcode() == ARP::REPLY) {
        // Let's check if there's already an entry for this address
        auto iter = addresses.find(arp.sender_ip_addr());
        if (iter == addresses.end()) {
            // We haven't seen this address. Save it.
            addresses.insert({ arp.sender_ip_addr(), arp.sender_hw_addr()});
            cout << "[INFO] " << arp.sender_ip_addr() << " is at "
                 << arp.sender_hw_addr() << std::endl;
        }
        else {
            // We've seen this address. If it's not the same HW address, inform it
            if (arp.sender_hw_addr() != iter->second) {
                cout << "[WARNING] " << arp.sender_ip_addr() << " is at " 
                     << iter->second << " but also at " << arp.sender_hw_addr() 
                     << endl;
            }
        }
    }
    return true;
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        cout << "Usage: " <<* argv << " <interface>" << endl;
        return 1;
    }
    arp_monitor monitor;
    // Sniffer configuration
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("arp");

    try {
        // Sniff on the provided interface in promiscuous mode
        Sniffer sniffer(argv[1], config);
        
        // Only capture arp packets
        monitor.run(sniffer);
    }
    catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
}
