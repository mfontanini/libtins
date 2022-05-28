/*
 * Copyright (c) 2017, Matias Fontanini
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

#include <tins/utils/routing_utils.h>
#ifndef _WIN32
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <sys/socket.h>
        #include <sys/file.h>
        #include <sys/sysctl.h>
        #include <net/route.h>
        #include <net/if_dl.h>
        #include <net/if.h>
        #include <netinet/in.h>
    #else
        #include <netpacket/packet.h>
    #endif
    #include <ifaddrs.h>
    #include <netdb.h>
    #include <net/if.h>
    #ifdef __ANDROID_API__
        #include <linux/in.h>
        #include <linux/in6.h>
    #endif
#else
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #undef interface
#endif
#include <set>
#include <fstream>
#include <tins/network_interface.h>
#include <tins/exceptions.h>

using std::vector;
using std::string;
using std::set;
using std::ifstream;
using std::istream;

namespace Tins {
namespace Utils {

struct InterfaceCollector {
    set<string> ifaces;
    
    #ifdef _WIN32
    bool operator() (PIP_ADAPTER_ADDRESSES addr) {
        ifaces.insert(addr->AdapterName);
        return false;
    }
    #else
    bool operator() (struct ifaddrs* addr) {
        ifaces.insert(addr->ifa_name);
        return false;
    }
    #endif
};

bool from_hex(const string& str, uint32_t& result) {
    size_t i = 0;
    result = 0;
    while (i < str.size()) {
        uint8_t tmp;
        if (str[i] >= 'A' && str[i] <= 'F') {
            tmp = (str[i] - 'A' + 10);
        }
        else if (str[i] >= '0' && str[i] <= '9') {
            tmp = (str[i] - '0');
        }
        else {
            return false;
        }
        result = (result << 4) | tmp;
        i++;
    }
    return true;
}

bool from_hex(const string& str, string& result) {
    result.clear();
    for (size_t i = 0; i < str.size(); i+= 2) {
        uint8_t value = 0;
        for (size_t j = i; j < i + 2 && j < str.size(); ++j) {
            if (str[j] >= 'A' && str[j] <= 'F') {
                value = (value << 4) | (str[j] - 'A' + 10);
            }
            else if (str[j] >= 'a' && str[j] <= 'f') {
                value = (value << 4) | (str[j] - 'a' + 10);
            }
            else if (str[j] >= '0' && str[j] <= '9') {
                value = (value << 4) | (str[j] - '0');
            }
            else {
                return false;
            }
        }
        result.push_back(value);
    }
    return true;
}

void skip_line(istream& input) {
    int c = 0;
    while (c != '\n' && input) {
        c = input.get();
    }
}

#if defined(BSD) || defined(__FreeBSD_kernel__)
vector<char> query_route_table(int family) {
    int mib[6];
    vector<char> buf;
    size_t len;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = family;
    mib[4] = NET_RT_DUMP;
    mib[5] = 0; 
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        throw exception_base("sysctl failed");
    }

    buf.resize(len);
    if (sysctl(mib, 6, &buf[0], &len, NULL, 0) < 0) {
        throw exception_base("sysctl failed");
    }

    buf.resize(len);
    return buf;
}

void parse_header(struct rt_msghdr* rtm, vector<sockaddr*>& addrs) {
    char* ptr = (char *)(rtm + 1);
    // Iterate from RTA_DST (0) to RTA_NETMASK (2)
    for (int i = 0; i < 3; ++i) {
        sockaddr* sa = 0;
        if ((rtm->rtm_addrs & (1 << i)) != 0) {
            sa = (struct sockaddr *)ptr;
            ptr += sa->sa_len;
            if (sa->sa_family == 0) {
                sa = 0;
            }
        } 
        addrs[i] = sa;
    }
}

vector<RouteEntry> route_entries() {
    vector<RouteEntry> output;
    vector<char> buffer = query_route_table(AF_INET);
    char* next = &buffer[0], *end = &buffer[buffer.size()];
    rt_msghdr* rtm;
    vector<sockaddr*> sa(32);
    char iface_name[IF_NAMESIZE];
    while (next < end) {
        rtm = (rt_msghdr*)next;
        // Filter:
        // * RTF_STATIC (only manually added routes)
        if ((rtm->rtm_flags & (RTF_STATIC)) != 0) {
            parse_header(rtm, sa);
            if (sa[RTAX_DST] && sa[RTAX_GATEWAY] && if_indextoname(rtm->rtm_index, iface_name)) {
                RouteEntry entry;
                entry.destination = IPv4Address(((struct sockaddr_in *)sa[RTAX_DST])->sin_addr.s_addr);
                entry.gateway = IPv4Address(((struct sockaddr_in *)sa[RTAX_GATEWAY])->sin_addr.s_addr);
                if (sa[RTAX_NETMASK]) {
                    entry.mask = IPv4Address(((struct sockaddr_in *)sa[RTAX_NETMASK])->sin_addr.s_addr);
                }
                entry.interface = iface_name;
                entry.metric = 0;
                output.push_back(entry);
            }
        }
        next += rtm->rtm_msglen;
    }
    return output;
}

vector<Route6Entry> route6_entries() {
    vector<Route6Entry> output;
    vector<char> buffer = query_route_table(AF_INET6);
    char* next = &buffer[0], *end = &buffer[buffer.size()];
    rt_msghdr* rtm;
    vector<sockaddr*> sa(9);
    char iface_name[IF_NAMESIZE];
    while (next < end) {
        rtm = (rt_msghdr*)next;
        // Filter protocol-cloned entries
        bool process_entry = true;
        // These were removed in recent versions of FreeBSD
        #if defined(RTF_WASCLONED) && defined(RTF_PRCLONING)
            process_entry = (rtm->rtm_flags & RTF_WASCLONED) == 0 ||
                            (rtm->rtm_flags & RTF_PRCLONING) == 0;
        #endif
        if (process_entry) {
            parse_header(rtm, sa);
            if (sa[RTAX_DST] && sa[RTAX_GATEWAY] && if_indextoname(rtm->rtm_index, iface_name)) {
                Route6Entry entry;
                entry.destination = IPv6Address(((struct sockaddr_in6 *)sa[RTAX_DST])->sin6_addr.s6_addr);
                entry.gateway = IPv6Address(((struct sockaddr_in6 *)sa[RTAX_GATEWAY])->sin6_addr.s6_addr);
                int prefix_length = 0;
                if (sa[RTAX_NETMASK]) {
                    struct sockaddr_in6  *sin = (struct sockaddr_in6 *)sa[RTAX_NETMASK];
                    for (size_t i = 0; i < 16; ++i) {
                        uint8_t this_byte = sin->sin6_addr.s6_addr[i];
                        // Stop when we find a zero byte
                        if (this_byte == 0) {
                            break;
                        }
                        switch (this_byte) {
                            case 0xff:
                                prefix_length += 8;
                                break;
                            case 0xfe:
                                prefix_length += 7;
                                break;
                            case 0xfc:
                                prefix_length += 6;
                                break;
                            case 0xf8:
                                prefix_length += 5;
                                break;
                            case 0xf0:
                                prefix_length += 4;
                                break;
                            case 0xe0:
                                prefix_length += 3;
                                break;
                            case 0xc0:
                                prefix_length += 2;
                                break;
                            case 0x80:
                                prefix_length += 1;
                                break;
                            default:
                                break;
                        }
                    }
                }
                entry.mask = IPv6Address::from_prefix_length(prefix_length);
                entry.interface = iface_name;
                entry.metric = 0;
                output.push_back(entry);
            }
        }
        next += rtm->rtm_msglen;
    }
    return output;
}

#elif defined(_WIN32)

vector<RouteEntry> route_entries() {
    vector<RouteEntry> output;
    MIB_IPFORWARDTABLE* table;
    ULONG size = 0;
    GetIpForwardTable(0, &size, 0);
    vector<uint8_t> buffer(size);
    table = (MIB_IPFORWARDTABLE*)&buffer[0];
    GetIpForwardTable(table, &size, 0);
    
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_IPFORWARDROW* row = &table->table[i];
        if (row->dwForwardType == MIB_IPROUTE_TYPE_INDIRECT || 
            row->dwForwardType == MIB_IPROUTE_TYPE_DIRECT) {
            RouteEntry entry;
            entry.interface = NetworkInterface::from_index(row->dwForwardIfIndex).name();
            entry.destination = IPv4Address(row->dwForwardDest);
            entry.mask = IPv4Address(row->dwForwardMask);
            entry.gateway = IPv4Address(row->dwForwardNextHop);
            entry.metric = row->dwForwardMetric1;
            output.push_back(entry);
        }
    }
    return output;
}

vector<Route6Entry> route6_entries() {
    vector<Route6Entry> output;
    MIB_IPFORWARD_TABLE2* table;
    GetIpForwardTable2(AF_INET6, &table);
    for (ULONG i = 0; i < table->NumEntries; i++) {
        MIB_IPFORWARD_ROW2* row = &table->Table[i];
        if (true) {
            try {
                Route6Entry entry;
                entry.interface = NetworkInterface::from_index(row->InterfaceIndex).name();
                entry.destination = IPv6Address(row->DestinationPrefix.Prefix.Ipv6.sin6_addr.s6_addr);
                entry.mask = IPv6Address::from_prefix_length(row->DestinationPrefix.PrefixLength);
                entry.gateway = IPv6Address(row->NextHop.Ipv6.sin6_addr.s6_addr);
                entry.metric = row->Metric;
                output.push_back(entry);
            }
            catch (const invalid_interface&) {
                
            }
        }
    }
    FreeMibTable(table);
    return output;
}

#else // GNU/LINUX

vector<RouteEntry> route_entries() {
    using namespace Tins::Internals;
    vector<RouteEntry> output;
    ifstream input("/proc/net/route");
    string destination, mask, metric, gw;
    uint32_t dummy;
    skip_line(input);
    RouteEntry entry;
    while (input >> entry.interface >> destination >> gw) {
        for (unsigned i(0); i < 4; ++i) {
            input >> metric;
        }
        input >> mask;
        from_hex(destination, dummy);
        entry.destination = IPv4Address(dummy);
        from_hex(mask, dummy);
        entry.mask = IPv4Address(dummy);
        from_hex(gw, dummy);
        entry.gateway = IPv4Address(dummy);
        from_hex(metric, dummy);
        entry.metric = dummy;
        skip_line(input);
        output.push_back(entry);
    }
    return output;
}

vector<Route6Entry> route6_entries() {
    using namespace Tins::Internals;
    vector<Route6Entry> output;
    ifstream input("/proc/net/ipv6_route");
    string destination, mask_length, metric, next_hop, dummy, flags;
    Route6Entry entry;
    while (input >> destination >> mask_length) {
        string temporary;
        uint32_t temporary_int;
        for (unsigned i(0); i < 2; ++i) {
            input >> dummy;
        }
        input >> next_hop;
        input >> metric;
        for (unsigned i(0); i < 2; ++i) {
            input >> dummy;
        }
        input >> flags >> entry.interface;
        from_hex(destination, temporary);
        entry.destination = IPv6Address((const uint8_t*)&temporary[0]);
        from_hex(mask_length, temporary_int);
        entry.mask = IPv6Address::from_prefix_length(temporary_int);
        from_hex(next_hop, temporary);
        entry.gateway = IPv6Address((const uint8_t*)&temporary[0]);
        from_hex(metric, temporary_int);
        entry.metric = temporary_int;
        // Process flags
        from_hex(flags, temporary_int);
        // Skip:
        // * 0x01000000 -> cache entries
        if ((temporary_int & 0x01000000) == 0) {
            output.push_back(entry);
        }
    }
    return output;
}

#endif

#ifdef _WIN32
set<string> network_interfaces() {
    set<string> output;
    ULONG size;
    ::GetAdaptersAddresses(AF_INET, 0, 0, 0, &size);
    vector<uint8_t> buffer(size);
    if (::GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)&buffer[0], &size) == ERROR_SUCCESS) {
        PIP_ADAPTER_ADDRESSES iface = (IP_ADAPTER_ADDRESSES *)&buffer[0];
        while (iface) {
            output.insert(iface->AdapterName);
            iface = iface->Next;
        }
    }
    return output;
}
#else
set<string> network_interfaces() {
    #ifndef ANDROID 
        set<string> output;
        struct ifaddrs* ifaddrs = 0;
        struct ifaddrs* if_it = 0;
        getifaddrs(&ifaddrs);
        for (if_it = ifaddrs; if_it; if_it = if_it->ifa_next) {
            output.insert(if_it->ifa_name);
        }
        if (ifaddrs) {
            freeifaddrs(ifaddrs);
        }
    return output;
    #else
        throw std::runtime_error("android ifaddr not supported");
    #endif
}
#endif // _WIN32

bool gateway_from_ip(IPv4Address ip, IPv4Address& gw_addr) {
    typedef vector<RouteEntry> entries_type;
    entries_type entries = route_entries();
    uint32_t ip_int = ip;
    for (entries_type::const_iterator it(entries.begin()); it != entries.end(); ++it) {
        if ((ip_int & it->mask) == it->destination) {
            gw_addr = it->gateway;
            return true;
        }
    }
    return false;
}

bool gateway_from_ip(IPv6Address ip, IPv6Address& gw_addr) {
    typedef vector<Route6Entry> entries_type;
    entries_type entries =route6_entries();
    for (entries_type::const_iterator it(entries.begin()); it != entries.end(); ++it) {
        if ((ip & it->mask) == it->destination) {
            gw_addr = it->gateway;
            return true;
        }
    }
    return false;
}

} // namespace Utils
} // namespace Tins
