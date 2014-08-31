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

#include <tins/tins.h>
#include <iostream>
#include <set>
#include <string>

using namespace Tins;

// BSSIDs which we've already seen
std::set<HWAddress<6>> addrs;
// This will be the content of the OUI field in the vendor specific 
// tagged option if it's a WPS tag.
const HWAddress<3> expected_oui("00:50:F2");

bool handler(const PDU& pdu) {
    const Dot11Beacon &beacon = pdu.rfind_pdu<Dot11Beacon>();
    // Only process it once
    if(addrs.insert(beacon.addr3()).second) {
        // Iterate the tagged options
        for(const auto &opt : beacon.options()) {
            // Is this a vendor-specific tag?
            if(opt.option() == Dot11::VENDOR_SPECIFIC) {
                // Make sure there's enough size for the OUI + identifier
                if(opt.data_size() >= 4) { 
                    // Retrieve the OUI field
                    HWAddress<3> addr = opt.data_ptr();
                    // Are we interested in this OUI and is it a WPS tag?
                    if(addr == expected_oui && opt.data_ptr()[3] == 0x04) {
                        std::cout << "[+] Access point: " << beacon.ssid() << " uses WPS\n";
                    }
                }
            }
        }
    }
    return true;
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        std::cout << "Usage: " << *argv << " <DEVICE>\n";
        return 1;
    }
    // Only sniff beacons
    SnifferConfiguration config;
    config.set_snap_len(2000);
    config.set_promisc_mode(true);
    config.set_filter("wlan type mgt subtype beacon");
    Sniffer sniffer(argv[1], config);
    sniffer.sniff_loop(handler);
}
