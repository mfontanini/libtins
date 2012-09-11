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
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/ip_address.h>
#include <tins/ethernetII.h>
#include <tins/network_interface.h>
#include <tins/sniffer.h>
#include <tins/utils.h>
#include <tins/packet_sender.h>


using namespace std;
using namespace Tins;

typedef std::pair<Sniffer*, std::string> sniffer_data;


/* Our scan handler. This will receive SYNs and RSTs and inform us
 * the scanned port's status.
 */
bool handler(PDU &pdu) {
    TCP *tcp = pdu.find_pdu<TCP>();
    if(tcp) {
        // Ok, it's a TCP PDU. Is RST flag on? Then port is closed.
        if(tcp->get_flag(TCP::RST)) {
            // This indicates we should stop sniffing.
            if(tcp->get_flag(TCP::SYN))
                return false;
            cout << "Port: " << setw(5) << tcp->sport() << " closed\n";
        }
        // Is SYN flag on? Then port is open!
        else if(tcp->get_flag(TCP::SYN) && tcp->get_flag(TCP::ACK))
            cout << "Port: " << setw(5) << tcp->sport() << " open\n";
    }
    return true;
}

// Send syns to the given ip address, using the destination ports provided.
void send_syns(const NetworkInterface &iface, IPv4Address dest_ip, const vector<string> &ips) {
    // Retrieve the addresses.
    NetworkInterface::Info info = iface.addresses();
    PacketSender sender;
    TCP *tcp = new TCP();
    // Allocate the IP PDU
    IP ip(dest_ip, info.ip_addr, tcp);
    // Set the SYN flag on.
    tcp->set_flag(TCP::SYN, 1);
    // Just some arbitrary port. 
    tcp->sport(1337);
    cout << "Sending SYNs..." << endl;
    for(vector<string>::const_iterator it = ips.begin(); it != ips.end(); ++it) {
        // Set the new port and send the packet!
        tcp->dport(atoi(it->c_str()));
        sender.send(ip);
    }
    // Wait 1 second.
    sleep(1);
    /* Special packet to indicate that we're done. This will be sniffed
     * by our function, which will in turn return false.  
     */
    tcp->set_flag(TCP::RST, 1);
    // Pretend we're the scanned host...
    ip.src_addr(dest_ip);
    // We use an ethernet pdu, otherwise the kernel will drop it.
    EthernetII eth(iface, info.hw_addr, info.hw_addr, ip.clone_pdu());
    sender.send(eth);
}

void *thread_proc(void *param) {
    // IP address is our parameter.
    sniffer_data *data = (sniffer_data*)param;
    Sniffer *sniffer = data->first;
    sniffer->set_filter("tcp and ip src " + data->second + " and tcp[tcpflags] & (tcp-rst|tcp-syn) != 0");
    // Sniff loop. Only sniff TCP PDUs comming from the given IP and have either RST or SYN flag on.
    sniffer->sniff_loop(handler);
    return 0;
}

void scan(int argc, char *argv[]) {
    IPv4Address ip(argv[1]);
    // Resolve the interface which will be our gateway
    NetworkInterface iface(ip);
    cout << "Sniffing on interface: " << iface.name() << endl;

    // 300 bytes are enough to receive SYNs and RSTs.
    Sniffer sniffer(iface.name(), 300);
    sniffer_data data(&sniffer, argv[1]);
    pthread_t thread;
    // Launch our sniff thread.
    pthread_create(&thread, 0, thread_proc, &data); 
    
    // Consume arguments
    argv += 2;
    argc -= 2;
    // Start sending SYNs to port.
    send_syns(iface, ip, vector<string>(argv, argv + (argc)));
    
    // Wait for our sniffer.
    void *dummy;
    pthread_join(thread, &dummy);
}

int main(int argc, char *argv[]) {
    if(argc < 3 && cout << "Usage: " << *argv << " <IPADDR> <port1> [port2] [port3]\n")
        return 1;
    try {
        scan(argc, argv);
    }
    catch(std::runtime_error &ex) {
        cout << "Error - " << ex.what() << endl;
    }
}
