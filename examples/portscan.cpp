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
#include <iomanip>
#include <vector>
#include <set>
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

using std::cout;
using std::endl;
using std::vector;
using std::pair;
using std::setw;
using std::string;
using std::set;
using std::runtime_error;

using namespace Tins;

typedef pair<Sniffer*, string> sniffer_data;

class Scanner {
public:
    Scanner(const NetworkInterface& interface, 
            const IPv4Address& address, 
            const vector<string>& ports);
    
    void run();
private:
    void send_syns(const NetworkInterface& iface, IPv4Address dest_ip);
    bool callback(PDU& pdu);
    static void* thread_proc(void* param);
    void launch_sniffer();
    
    NetworkInterface iface;
    IPv4Address host_to_scan;
    set<uint16_t> ports_to_scan;
    Sniffer sniffer;
};

Scanner::Scanner(const NetworkInterface& interface, 
                 const IPv4Address& address, 
                 const vector<string>& ports)
: iface(interface), host_to_scan(address), sniffer(interface.name()) {
    sniffer.set_filter(
        "tcp and ip src " + address.to_string() + " and tcp[tcpflags] & (tcp-rst|tcp-syn) != 0"
    );
    for (size_t i = 0; i < ports.size(); ++i) {
        ports_to_scan.insert(atoi(ports[i].c_str()));
    }
}

void* Scanner::thread_proc(void* param) {
    Scanner* data = (Scanner*)param;
    data->launch_sniffer();
    return 0;
}

void Scanner::launch_sniffer() {
    sniffer.sniff_loop(make_sniffer_handler(this, &Scanner::callback));
}

/* Our scan handler. This will receive SYNs and RSTs and inform us
 * the scanned port's status.
 */
bool Scanner::callback(PDU& pdu) {
    // Find the layers we want.
    const IP& ip = pdu.rfind_pdu<IP>();
    const TCP& tcp = pdu.rfind_pdu<TCP>();
    // Check if the host that we're scanning sent this packet and
    // the source port is one of those that we scanned.
    if(ip.src_addr() == host_to_scan && ports_to_scan.count(tcp.sport()) == 1) {
        // Ok, it's a TCP PDU. Is RST flag on? Then port is closed.
        if(tcp.get_flag(TCP::RST)) {
            // This indicates we should stop sniffing.
            if(tcp.get_flag(TCP::SYN))
                return false;
            cout << "Port: " << setw(5) << tcp.sport() << " closed\n";
        }
        // Is SYN flag on? Then port is open!
        else if(tcp.flags() == (TCP::SYN | TCP::ACK)) {
            cout << "Port: " << setw(5) << tcp.sport() << " open\n";
        }
    }
    return true;
}

void Scanner::run() {
    pthread_t thread;
    // Launch our sniff thread.
    pthread_create(&thread, 0, &Scanner::thread_proc, this); 
    // Start sending SYNs to port.
    send_syns(iface, host_to_scan);

    // Wait for our sniffer.
    void* dummy;
    pthread_join(thread, &dummy);
}

// Send syns to the given ip address, using the destination ports provided.
void Scanner::send_syns(const NetworkInterface& iface, IPv4Address dest_ip) {
    // Retrieve the addresses.
    NetworkInterface::Info info = iface.addresses();
    PacketSender sender;
    // Allocate the IP PDU
    IP ip = IP(dest_ip, info.ip_addr) / TCP();
    // Get the reference to the TCP PDU
    TCP& tcp = ip.rfind_pdu<TCP>();
    // Set the SYN flag on.
    tcp.set_flag(TCP::SYN, 1);
    // Just some random port. 
    tcp.sport(1337);
    cout << "Sending SYNs..." << endl;
    for (set<uint16_t>::const_iterator it = ports_to_scan.begin(); it != ports_to_scan.end(); ++it) {
        // Set the new port and send the packet!
        tcp.dport(*it);
        sender.send(ip);
    }
    // Wait 1 second.
    sleep(1);
    /* Special packet to indicate that we're done. This will be sniffed
     * by our function, which will in turn return false.  
     */
    tcp.set_flag(TCP::RST, 1);
    tcp.sport(*ports_to_scan.begin());
    // Pretend we're the scanned host...
    ip.src_addr(dest_ip);
    // We use an ethernet pdu, otherwise the kernel will drop it.
    EthernetII eth = EthernetII(info.hw_addr, info.hw_addr) / ip;
    sender.send(eth, iface);
}

void scan(int argc, char* argv[]) {
    IPv4Address ip(argv[1]);
    // Resolve the interface which will be our gateway
    NetworkInterface iface(ip);
    cout << "Sniffing on interface: " << iface.name() << endl;
    
    // Consume arguments
    argv += 2;
    argc -= 2;
    Scanner scanner(iface, ip, vector<string>(argv, argv + (argc)));
    scanner.run();
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " <<* argv << " <IPADDR> <port1> [port2] [port3]" << endl;
        return 1;
    }
    try {
        scan(argc, argv);
    }
    catch(runtime_error& ex) {
        cout << "Error - " << ex.what() << endl;
    }
}
