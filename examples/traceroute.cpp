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
 
#ifdef _WIN32
    #define NOMINMAX
#endif // _WIN32

// Fix for gcc 4.6
#define _GLIBCXX_USE_NANOSLEEP

#include <iostream>
#include <chrono>
#include <thread>
#include <cstdint>
#include <random>
#include <map>
#include <algorithm>
#include <atomic>
#include <limits>
#include <mutex>
#include <tins/tins.h>

using std::cout;
using std::endl;
using std::move;
using std::map;
using std::min;
using std::setw;
using std::atomic;
using std::runtime_error;
using std::string;
using std::to_string;
using std::thread;
using std::this_thread::sleep_for;
using std::lock_guard;
using std::mutex;
using std::random_device;
using std::numeric_limits;
using std::bind;
using std::chrono::milliseconds;

using namespace Tins;

class Traceroute {
public:
    typedef std::map<uint16_t, IPv4Address> result_type;

    Traceroute(NetworkInterface interface, IPv4Address address) 
    : iface(interface), addr(address), lowest_dest_ttl(numeric_limits<int>::max()) { 
        sequence = random_device()() & 0xffff;
    }
    
    result_type trace() {
        SnifferConfiguration config;
        config.set_promisc_mode(false);
        // ICMPs that aren't sent from us.
        config.set_filter(
            "ip proto \\icmp and not src host " + iface.addresses().ip_addr.to_string());
        Sniffer sniffer(iface.name(), config);
        
        PacketSender sender;
        // Create our handler
        auto handler = bind(
            &Traceroute::sniff_callback, 
            this, 
            std::placeholders::_1
        );
        // We're running
        running = true;
        // Start the sniff thread
        thread sniff_thread(
            [&]() {
                sniffer.sniff_loop(handler);
            }
        );
        send_packets(sender);
        sniff_thread.join();
        // If the final hop responded, add its address at the appropriate ttl
        if (lowest_dest_ttl != numeric_limits<int>::max()) {
            results[lowest_dest_ttl] = addr;
        }
        // Clear our results and return what we've found
        return move(results);
    }
private:
    typedef map<uint16_t, size_t> ttl_map;

    void send_packets(PacketSender& sender) {
        // ICMPs are icmp-requests by default
        IP ip = IP(addr, iface.addresses().ip_addr) / ICMP();
        ICMP& icmp = ip.rfind_pdu<ICMP>();
        icmp.sequence(sequence);
        // We'll find at most 20 hops.
        
        for (auto i = 1; i <= 20; ++i) {
            // Set this ICMP id
            icmp.id(i);
            // Set the time-to-live option
            ip.ttl(i);
            
            // Critical section
            {
                lock_guard<mutex> _(lock);
                ttls[i] = i;
            }
            
            sender.send(ip);
            // Give it a little time
            sleep_for(milliseconds(100));
        }
        running = false;
        sender.send(ip);
    }

    bool sniff_callback(PDU& pdu) {
        // Find IP and ICMP PDUs
        const IP& ip = pdu.rfind_pdu<IP>();
        const ICMP& icmp = pdu.rfind_pdu<ICMP>();
        // Check if this is an ICMP TTL exceeded error response
        if (icmp.type() == ICMP::TIME_EXCEEDED) {
            // Fetch the IP PDU attached to the ICMP response
            const IP inner_ip = pdu.rfind_pdu<RawPDU>().to<IP>();
            // Now get the ICMP layer
            const ICMP& inner_icmp = inner_ip.rfind_pdu<ICMP>();
            // Make sure this is one of our packets.
            if (inner_icmp.sequence() == sequence) {
                ttl_map::const_iterator iter;

                // Critical section
                {
                    std::lock_guard<std::mutex> _(lock);
                    iter = ttls.find(inner_icmp.id());
                } 

                // It's an actual response
                if(iter != ttls.end()) {
                    // Store it
                    results[inner_icmp.id()] = ip.src_addr();
                }
            }
        }
        // Otherwise, this could be the final hop making an echo response
        else if (icmp.type() == ICMP::ECHO_REPLY && icmp.sequence() == sequence && 
                ip.src_addr() == addr) {
            // Keep the lowest ttl seen for the destination.
            lowest_dest_ttl = min(lowest_dest_ttl, static_cast<int>(icmp.id()));
        }
        return running;
    }

    NetworkInterface iface;
    IPv4Address addr;
    atomic<bool> running;
    ttl_map ttls;
    result_type results;
    mutex lock;
    uint16_t sequence;
    int lowest_dest_ttl;
};

int main(int argc, char* argv[]) {
    if (argc <= 1) { 
        cout << "Usage: " <<* argv << " <ip_address>" << endl;
        return 1;
    }
    try {
        IPv4Address addr = string(argv[1]);
        Traceroute tracer(addr, addr);
        auto results = tracer.trace();
        if (results.empty()) {
            cout << "No hops found" << endl;
        }
        else {
            cout << "Results: " << endl;
            for(const auto& entry : results) {
                cout << setw(2) << entry.first << " - " << entry.second << endl;
            }
        }
    }
    catch (runtime_error& ex) {
        cout << "Error - " << ex.what() << endl;
        return 2;
    }
}
