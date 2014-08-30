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
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>
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
    const TCP &tcp = pdu.rfind_pdu<TCP>();
    // Ok, it's a TCP PDU. Is RST flag on? Then port is closed.
    if(tcp.get_flag(TCP::RST)) {
        // This indicates we should stop sniffing.
        if(tcp.get_flag(TCP::SYN))
            return false;
        cout << "Port: " << setw(5) << tcp.sport() << " closed\n";
    }
    // Is SYN flag on? Then port is open!
    else if(tcp.flags() == (TCP::SYN | TCP::ACK))
        cout << "Port: " << setw(5) << tcp.sport() << " open\n";
    return true;
}

// Send syns to the given ip address, using the destination ports provided.
void send_syns(const NetworkInterface &iface, IPv4Address dest_ip, const vector<string> &ips) {
    // Retrieve the addresses.
    NetworkInterface::Info info = iface.addresses();
    PacketSender sender;
    // Allocate the IP PDU
    IP ip = IP(dest_ip, info.ip_addr) / TCP();
    // Get the reference to the TCP PDU
    TCP &tcp = ip.rfind_pdu<TCP>();
    // Set the SYN flag on.
    tcp.set_flag(TCP::SYN, 1);
    // Just some random port. 
    tcp.sport(1337);
    cout << "Sending SYNs..." << endl;
    for(vector<string>::const_iterator it = ips.begin(); it != ips.end(); ++it) {
        // Set the new port and send the packet!
        tcp.dport(atoi(it->c_str()));
        sender.send(ip);
    }
    // Wait 1 second.
    sleep(1);
    /* Special packet to indicate that we're done. This will be sniffed
     * by our function, which will in turn return false.  
     */
    tcp.set_flag(TCP::RST, 1);
    // Pretend we're the scanned host...
    ip.src_addr(dest_ip);
    // We use an ethernet pdu, otherwise the kernel will drop it.
    EthernetII eth = EthernetII(info.hw_addr, info.hw_addr) / ip;
    sender.send(eth, iface);
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
    SnifferConfiguration config;
    config.set_snap_len(300);
    Sniffer sniffer(iface.name(), config);
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
