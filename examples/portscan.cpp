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

struct ThreadData {
    string interface;
    string ip;
};

struct ScanHandler {
    bool operator() (PDU *pdu) {
        EthernetII *eth = dynamic_cast<EthernetII*>(pdu);
        if(eth) {
            IP *ip = dynamic_cast<IP*>(pdu->inner_pdu());
            if(ip) {
                TCP *tcp = dynamic_cast<TCP*>(ip->inner_pdu());
                if(tcp) {
                    if(tcp->get_flag(TCP::RST))
                        cout << "Port: " << tcp->sport() << " closed\n";
                    else if(tcp->get_flag(TCP::SYN))
                        cout << "Port: " << tcp->sport() << " open\n";
                }
            }
        }
        return true;
    }
};


Sniffer *sniffer;

void send_syns(const string &iface, uint32_t dest_ip, int argc, char *argv[]) {
    uint32_t own_ip;
    if(!Utils::interface_ip(iface, own_ip) && cout << "Error obtaining interface ip.\n")
        return;
    PacketSender sender;
    TCP *tcp = new TCP();
    IP ip(dest_ip, own_ip, tcp);
    tcp->set_flag(TCP::SYN, 1);
    while(argc--) {
        uint32_t port = atoi(*(argv++));
        tcp->dport(port);
        sender.send(&ip);
    }
}

void *thread_proc(void *param) {
    ThreadData *data = (ThreadData*)param;
    ScanHandler handler;
    AbstractSnifferHandler *my_handler = new SnifferHandler<ScanHandler>(&handler);
    sniffer->sniff_loop("tcp and ip src " + data->ip, my_handler);
    cout << "Listo\n";
    delete my_handler;
    return 0;
}

int main(int argc, char *argv[]) {
    if(argc < 3 && cout << "Usage: " << *argv << " <IPADDR> <port1> [port2] [port3]\n")
        return 1;
    uint32_t ip;
    try {
        ip = Utils::resolve_ip(argv[1]);
    }
    catch(...) {
        cout << "IP address is not valid.\n";
        return 2;
    }    
    string iface = Utils::interface_from_ip(ip);
    if(!iface.size() && cout << "Could not locate gateway interface for given ip address\n")
        return 3;
    sniffer = new Sniffer(iface, 300);
    ThreadData data;
    data.interface = iface;
    data.ip = argv[1];
    pthread_t thread;
    pthread_create(&thread, 0, thread_proc, &data); 
    
    send_syns(iface, ip, argc - 2, argv + 2);
    
    sleep(5);
    
    pthread_cancel(thread);
    delete sniffer;
}
