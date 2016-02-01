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
#include <set>
#include <string>
#include <tins/tins.h>
 
using std::set;
using std::cout;
using std::endl;
using std::string;
using std::runtime_error;

using namespace Tins;
 
class BeaconSniffer {
public:
    void run(const string& iface);
private:
    typedef Dot11::address_type address_type;
    typedef set<address_type> ssids_type;
 
    bool callback(PDU& pdu);
     
    ssids_type ssids;
};
 
void BeaconSniffer::run(const std::string& iface) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("type mgt subtype beacon");
    config.set_rfmon(true);
    Sniffer sniffer(iface, config);
    sniffer.sniff_loop(make_sniffer_handler(this, &BeaconSniffer::callback));
}
 
bool BeaconSniffer::callback(PDU& pdu) {
    // Get the Dot11 layer
    const Dot11Beacon& beacon = pdu.rfind_pdu<Dot11Beacon>();
    // All beacons must have from_ds == to_ds == 0
    if (!beacon.from_ds() && !beacon.to_ds()) {
        // Get the AP address
        address_type addr = beacon.addr2();
        // Look it up in our set
        ssids_type::iterator it = ssids.find(addr);
        if (it == ssids.end()) {
            // First time we encounter this BSSID.
            try {
                /* If no ssid option is set, then Dot11::ssid will throw 
                 * a std::runtime_error.
                 */
                string ssid = beacon.ssid();
                // Save it so we don't show it again.
                ssids.insert(addr);
                // Display the tuple "address - ssid".
                cout << addr << " - " << ssid << endl;
            }
            catch (runtime_error&) {
                // No ssid, just ignore it.
            }
        }
    }
    return true;
}
 
int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " <<* argv << " <interface>" << endl;
        return 1;
    }
    string interface = argv[1];
    BeaconSniffer sniffer;
    sniffer.run(interface);
}
