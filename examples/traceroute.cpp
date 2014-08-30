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
        SnifferConfiguration config;
        config.set_snap_len(500);
        config.set_promisc_mode(false);
        config.set_filter(
            "ip proto \\icmp and not src host " + iface.addresses().ip_addr.to_string());
        Sniffer sniffer(iface.name(), config);
        
        PacketSender sender;
        // Create our handler
        auto handler = std::bind(
            &Traceroute::sniff_callback, 
            this, 
            std::placeholders::_1
        );
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
        IP ip = IP(addr, iface.addresses().ip_addr) / ICMP();
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
        const IP &ip = pdu.rfind_pdu<IP>();
        ttl_map::const_iterator iter;
        // Fetch the IP PDU attached to the ICMP response
        const IP inner_ip = pdu.rfind_pdu<RawPDU>().to<IP>();
        // Critical section
        {
            std::lock_guard<std::mutex> _(lock);
            iter = ttls.find(inner_ip.id());
        } 

        // It's an actual response
        if(iter != ttls.end()) {
            // Store it
            results[inner_ip.id()] = ip.src_addr();
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
