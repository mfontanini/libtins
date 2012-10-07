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
 * 
 * 
 * Simple traceroute utility. It will probably miss some hops, since
 * it doesn't wait much for hosts to answer.
 */
 
#include <iostream>
#include <chrono>
#include <thread>
#include <cstdint>
#include <map>
#include <atomic>
#include <mutex>
#include <tins/tins.h>

using namespace Tins;

class Traceroute {
public:
    typedef std::map<uint16_t, IPv4Address> result_type;

    Traceroute(NetworkInterface interface, IPv4Address address) 
      : iface(interface), addr(address) { }
    
    result_type trace() {
        // ICMPs that aren't sent from us.
        Sniffer sniffer(
            iface.name(), 500, false, 
            "ip proto \\icmp and not src host " + iface.addresses().ip_addr.to_string()
        );
        
        PacketSender sender;
        // Create our handler
        auto handler = make_sniffer_handler(this, &Traceroute::sniff_callback);
        // We're running
        running = true;
        // Start the sniff thread
        std::thread sniff_thread(
            &Sniffer::sniff_loop<decltype(handler)>, 
            &sniffer, 
            handler,
            0
        );
        send_packets(sender);
        sniff_thread.join();
        // Clear our results and return what we've found
        return std::move(results);
    }
private:
    typedef std::map<uint16_t, size_t> ttl_map;

    void send_packets(PacketSender &sender) {
        // ICMPs are icmp-requests by default
        IP ip(addr, iface.addresses().ip_addr, new ICMP());
        // We'll find at most 10 hops.
        for(auto i = 1; i <= 10; ++i) {
            // Set this "unique" id
            ip.id(i);
            // Set the time-to-live option
            ip.ttl(i);
            
            // Critical section
            {
                std::lock_guard<std::mutex> _(lock);
                ttls[i] = i;
            }
            
            sender.send(ip);
            // Give him a little time
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        running = false;
        sender.send(ip);
    }

    bool sniff_callback(PDU &pdu) {
        IP *ip = pdu.find_pdu<IP>();
        RawPDU *raw = pdu.find_pdu<RawPDU>();
        if(ip && raw) {
            ttl_map::const_iterator iter;
            IP inner_ip;
            // This will fail if its a corrupted packet
            try {
                // Fetch the IP PDU attached to the ICMP response
                inner_ip = IP(&raw->payload()[0], raw->payload_size());
            }
            catch(std::runtime_error &ex) {
                return running;
            }
            // Critical section
            {
                std::lock_guard<std::mutex> _(lock);
                iter = ttls.find(inner_ip.id());
            } 

            // It's an actual response
            if(iter != ttls.end()) {
                // Store it
                results[inner_ip.id()] = ip->src_addr();
            }
        }
        return running;
    }

    NetworkInterface iface;
    IPv4Address addr;
    std::atomic<bool> running;
    ttl_map ttls;
    result_type results;
    std::mutex lock;
};

int main(int argc, char* argv[]) {
    if(argc <= 1 && std::cout << "Usage: " << *argv << " <IP_ADDRESS>\n") 
        return 1;
    try {
        IPv4Address addr((std::string(argv[1])));
        Traceroute tracer(addr, addr);
        auto results = tracer.trace();
        if(results.empty())
            std::cout << "No hops found" << std::endl;
        else {
            std::cout << "Results: " << std::endl;
            for(const auto &entry : results) {
                std::cout << entry.first << " - " << entry.second << std::endl;
            }
        }
    }
    catch(std::runtime_error &ex) {
        std::cout << "Error - " << ex.what() << std::endl;
        return 2;
    }
}
