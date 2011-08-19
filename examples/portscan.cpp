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
#include <cstdlib>
#include <pthread.h>
#include "ip.h"
#include "tcp.h"
#include "ethernetII.h"
#include "sniffer.h"
#include "utils.h"
#include "packetsender.h"


using namespace std;
using namespace Tins;


/* Our scan handler. This will receive SYNs and RSTs and inform us
 * the scanned port's status.
 */
struct ScanHandler {
    bool operator() (PDU *pdu) {
        // Down-cast the inner PDU to IP.
        IP *ip = dynamic_cast<IP*>(pdu->inner_pdu());
        if(ip) {
            // Down-cast IP's inner PDU to TCP.
            TCP *tcp = dynamic_cast<TCP*>(ip->inner_pdu());
            if(tcp) {
                // Ok, it's a TCP PDU. Is RST flag on? Then port is closed.
                if(tcp->get_flag(TCP::RST))
                    cout << "Port: " << tcp->sport() << " closed\n";
                // Is SYN flag on? Then port is open!
                else if(tcp->get_flag(TCP::SYN))
                    cout << "Port: " << tcp->sport() << " open\n";
            }
        }
        return true;
    }
};


Sniffer *sniffer;

// Send syns to the given ip address, using the destination ports provided.
void send_syns(const string &iface, uint32_t dest_ip, int argc, char *argv[]) {
    uint32_t own_ip;
    // Resolve our ip on that interface.
    if(!Utils::interface_ip(iface, own_ip) && cout << "Error obtaining interface ip.\n")
        return;
    PacketSender sender;
    TCP *tcp = new TCP();
    // Allocate the IP PDU
    IP ip(dest_ip, own_ip, tcp);
    // Set the SYN flag on.
    tcp->set_flag(TCP::SYN, 1);
    // Just some arbitrary port. 
    tcp->sport(1337);
    while(argc--) {
        // Set the new port and send the packet!
        uint32_t port = atoi(*(argv++));
        tcp->dport(port);
        sender.send(&ip);
    }
}

void *thread_proc(void *param) {
    // IP address is our parameter.
    string *data = (string*)param;
    // The scan handler.
    ScanHandler handler;
    // The required subclass of AbstractSnifferHandler which will serve as
    // a proxy to our handler.
    AbstractSnifferHandler *my_handler = new SnifferHandler<ScanHandler>(&handler);
    // Sniff loop. Only sniff TCP PDUs comming from the given IP and have either RST or SYN flag on.
    sniffer->sniff_loop(my_handler, "tcp and ip src " + *data + " and tcp[tcpflags] & (tcp-rst|tcp-syn) != 0");
    delete my_handler;
    return 0;
}

int main(int argc, char *argv[]) {
    if(argc < 3 && cout << "Usage: " << *argv << " <IPADDR> <port1> [port2] [port3]\n")
        return 1;
    uint32_t ip;
    try {
        // Resolve the ip address
        ip = Utils::resolve_ip(argv[1]);
    }
    catch(...) {
        cout << "IP address is not valid.\n";
        return 2;
    }
    // Resolve the interface which will be our gateway
    string iface = Utils::interface_from_ip(ip);
    if(!iface.size() && cout << "Could not locate gateway interface for given ip address\n")
        return 3;
        
    // Allocate our sniffer. 300 bytes are enough to receive SYNs and RSTs.
    sniffer = new Sniffer(iface, 300);

    string ip_string = argv[1];
    pthread_t thread;
    // Launch our sniff thread.
    pthread_create(&thread, 0, thread_proc, &ip_string); 
    
    // Start sending SYNs to port.
    send_syns(iface, ip, argc - 2, argv + 2);
    
    // Give it some time...
    sleep(5);
    
    // Ok, we kill our sniffer.
    pthread_cancel(thread);
    delete sniffer;
}
