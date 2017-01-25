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

#include "packet_sender.h"
#ifndef _WIN32
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <sys/ioctl.h>
        #include <sys/types.h>
        #include <sys/stat.h>
        #include <fcntl.h>
        #include <net/if.h>
        #include <net/bpf.h>
    #else
        #include <linux/if_ether.h>
        #include <linux/if_packet.h>
    #endif
    #include <netdb.h>
    #include <netinet/in.h>
    #include <errno.h>
#else
    #include <winsock2.h>
    #include <ws2tcpip.h>
#endif
#include <cstring>
#include <ctime>
#include <algorithm>
#include "pdu.h"
#include "macros.h"
#include "network_interface.h"
// PDUs required by PacketSender::send(PDU&, NetworkInterface)
#include "ethernetII.h"
#include "radiotap.h"
#include "dot11/dot11_base.h"
#include "radiotap.h"
#include "ieee802_3.h"
#include "internals.h"
#include "cxxstd.h"
#if TINS_IS_CXX11
    #include <chrono>
#endif // TINS_IS_CXX11

using std::string;
using std::ostringstream;
using std::max;
using std::make_pair;
using std::vector;
using std::runtime_error;

namespace Tins {

const int PacketSender::INVALID_RAW_SOCKET = -1;
const uint32_t PacketSender::DEFAULT_TIMEOUT = 2;

#ifndef _WIN32
    typedef int socket_type;
    
    const char* make_error_string() {
        return strerror(errno);
    }
#else
    typedef SOCKET socket_type;

    // fixme
    const char* make_error_string() {
        return "error";
    }
#endif

PacketSender::PacketSender(const NetworkInterface& iface, 
                           uint32_t recv_timeout, 
                           uint32_t usec) 
: sockets_(SOCKETS_END, INVALID_RAW_SOCKET), 
#if !defined(BSD) && !defined(_WIN32) && !defined(__FreeBSD_kernel__)
  ether_socket_(INVALID_RAW_SOCKET),
#endif
  _timeout(recv_timeout), timeout_usec_(usec), default_iface_(iface) {
    types_[IP_TCP_SOCKET] = IPPROTO_TCP;
    types_[IP_UDP_SOCKET] = IPPROTO_UDP;
    types_[IP_RAW_SOCKET] = IPPROTO_RAW;
    types_[IPV6_SOCKET] = IPPROTO_RAW;
    types_[ICMP_SOCKET] = IPPROTO_ICMP;
}

PacketSender::~PacketSender() {
    for (unsigned i(0); i < sockets_.size(); ++i) {
        if (sockets_[i] != INVALID_RAW_SOCKET)  {
            #ifndef _WIN32
                ::close(sockets_[i]);
            #else
                ::closesocket(sockets_[i]);
            #endif
        }
    }
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        for (BSDEtherSockets::iterator it = ether_socket_.begin(); 
             it != ether_socket_.end(); ++it) {
            ::close(it->second);
        }
    #elif !defined(_WIN32)
        if (ether_socket_ != INVALID_RAW_SOCKET) {
            ::close(ether_socket_);
        }
    #endif

    #ifdef TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET
        for (PcapHandleMap::iterator it = pcap_handles_.begin(); it != pcap_handles_.end(); ++it) {
            pcap_close(it->second);
        }
        pcap_handles_.clear();
    #endif // TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET
}

void PacketSender::default_interface(const NetworkInterface& iface) {
    default_iface_ = iface;
}

const NetworkInterface& PacketSender::default_interface() const {
    return default_iface_;
}

#if !defined(_WIN32) || defined(TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET)

#ifndef _WIN32
bool PacketSender::ether_socket_initialized(const NetworkInterface& iface) const {
    #if defined(BSD) || defined(__FreeBSD_kernel__)
    return ether_socket_.count(iface.id());
    #else
    Internals::unused(iface);
    return ether_socket_ != INVALID_RAW_SOCKET;
    #endif
}

int PacketSender::get_ether_socket(const NetworkInterface& iface) {
    if (!ether_socket_initialized(iface)) {
        open_l2_socket(iface);
    }
    #if defined(BSD) || defined(__FreeBSD_kernel__)
    return ether_socket_[iface.id()];
    #else
    return ether_socket_;
    #endif
}
#endif // _WIN32

#ifdef TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET

pcap_t* PacketSender::make_pcap_handle(const NetworkInterface& iface) const {
    // This is an ugly fix to make interface names look like what 
    // libpcap expects on Windows
    #ifdef _WIN32
        #define TINS_PREFIX_INTERFACE(x) ("\\Device\\NPF_" + x)
    #else // _WIN32
        #define TINS_PREFIX_INTERFACE(x) (x)
    #endif // _WIN32

    char error[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_create(TINS_PREFIX_INTERFACE(iface.name()).c_str(), error);
    if (!handle) {
        throw runtime_error("Error opening pcap handle: " + string(error));
    }
    if (pcap_set_promisc(handle, 1) < 0) {
        throw runtime_error("Failed to set pcap handle promisc mode: " + string(pcap_geterr(handle)));
    }
    if (pcap_activate(handle) < 0) {
        throw runtime_error("Failed to activate pcap handle: " + string(pcap_geterr(handle)));
    }
    return handle;
}

#endif // TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET

void PacketSender::open_l2_socket(const NetworkInterface& iface) {
    #ifdef TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET
        if (pcap_handles_.count(iface) == 0) {
            pcap_handles_.insert(make_pair(iface, make_pcap_handle(iface)));
        }
    #elif defined(BSD) || defined(__FreeBSD_kernel__)
        int sock = -1;
        // At some point, there should be an available device
        for (int i = 0; sock == -1;i++) {
            ostringstream oss;
            oss << "/dev/bpf" << i;

            sock = open(oss.str().c_str(), O_RDWR);
        }
        if (sock == -1) {
            throw socket_open_error(make_error_string());
        }
        
        struct ifreq ifr;
        strncpy(ifr.ifr_name, iface.name().c_str(), sizeof(ifr.ifr_name) - 1);
        if (ioctl(sock, BIOCSETIF, (caddr_t)&ifr) < 0) {
            ::close(sock);
            throw socket_open_error(make_error_string());
        }
        // Use immediate mode
        u_int value = 1;
        if (ioctl(sock, BIOCIMMEDIATE, &value) < 0) {
            throw socket_open_error(make_error_string());
        }
        // Get the buffer size
        if (ioctl(sock, BIOCGBLEN, &buffer_size_) < 0) {
            throw socket_open_error(make_error_string());
        }
        ether_socket_[iface.id()] = sock;
    #else
    Internals::unused(iface);
    if (ether_socket_ == INVALID_RAW_SOCKET) {
        ether_socket_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        
        if (ether_socket_ == -1) {
            throw socket_open_error(make_error_string());
        }
    }
    #endif
}
#endif // !_WIN32 || TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET

void PacketSender::open_l3_socket(SocketType type) {
    int socktype = find_type(type);
    if (socktype == -1) {
        throw invalid_socket_type();
    }
    if (sockets_[type] == INVALID_RAW_SOCKET) {
        socket_type sockfd;
        sockfd = socket((type == IPV6_SOCKET) ? AF_INET6 : AF_INET, SOCK_RAW, socktype);
        if (sockfd < 0) {
            throw socket_open_error(make_error_string());
        }

        const int on = 1;
        #ifndef _WIN32
        typedef const void* option_ptr;
        #else
        typedef const char* option_ptr;
        #endif
        const int level = (type == IPV6_SOCKET) ? IPPROTO_IPV6 : IPPROTO_IP;
        if (setsockopt(sockfd, level, IP_HDRINCL, (option_ptr)&on, sizeof(on)) != 0) {
            throw socket_open_error(make_error_string());
        }

        sockets_[type] = static_cast<int>(sockfd);
    }
}

void PacketSender::close_socket(SocketType type, const NetworkInterface& iface) {
    if (type == ETHER_SOCKET) {
        #if defined(BSD) || defined(__FreeBSD_kernel__)
        BSDEtherSockets::iterator it = ether_socket_.find(iface.id());
        if (it == ether_socket_.end()) {
            throw invalid_socket_type();
        }
        if (::close(it->second) == -1) {
            throw socket_close_error(make_error_string());
        }
        ether_socket_.erase(it);
        #elif !defined(_WIN32)
        Internals::unused(iface);
        if (ether_socket_ == INVALID_RAW_SOCKET) {
            throw invalid_socket_type();
        }
        if (::close(ether_socket_) == -1) {
            throw socket_close_error(make_error_string());
        }
        ether_socket_ = INVALID_RAW_SOCKET;
        #endif
    }
    else {
        Internals::unused(iface);
        if (type >= SOCKETS_END || sockets_[type] == INVALID_RAW_SOCKET) {
            throw invalid_socket_type();
        }
        #ifndef _WIN32
        if (close(sockets_[type]) == -1) {
            throw socket_close_error(make_error_string());
        }
        #else
        closesocket(sockets_[type]);
        #endif
        sockets_[type] = INVALID_RAW_SOCKET;
    }
}

void PacketSender::send(PDU& pdu) {
    pdu.send(*this, default_iface_);
}

void PacketSender::send(PDU& pdu, const NetworkInterface& iface) {
    if (pdu.matches_flag(PDU::ETHERNET_II)) {
        send<Tins::EthernetII>(pdu, iface);
    }
    #ifdef TINS_HAVE_DOT11
        else if (pdu.matches_flag(PDU::DOT11)) {
            send<Tins::Dot11>(pdu, iface);
        }
        else if (pdu.matches_flag(PDU::RADIOTAP)) {
            send<Tins::RadioTap>(pdu, iface);
        }
    #endif // TINS_HAVE_DOT11
    else if (pdu.matches_flag(PDU::IEEE802_3)) {
        send<Tins::IEEE802_3>(pdu, iface);
    }
    else {
        send(pdu);
    }
}

PDU* PacketSender::send_recv(PDU& pdu) {
    return send_recv(pdu, default_iface_);
}

PDU* PacketSender::send_recv(PDU& pdu, const NetworkInterface& iface) {
    try {
        pdu.send(*this, iface);
    }
    catch (runtime_error&) {
        return 0;
    }
    return pdu.recv_response(*this, iface);
}

#if !defined(_WIN32) || defined(TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET)
void PacketSender::send_l2(PDU& pdu,
                           struct sockaddr* link_addr, 
                           uint32_t len_addr,
                           const NetworkInterface& iface) {
    PDU::serialization_type buffer = pdu.serialize();

    #ifdef TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET
        Internals::unused(len_addr);
        Internals::unused(link_addr);
        open_l2_socket(iface);
        pcap_t* handle = pcap_handles_[iface];
        const int buf_size = static_cast<int>(buffer.size());
        if (pcap_sendpacket(handle, (u_char*)&buffer[0], buf_size) != 0) {
            throw runtime_error("Failed to send packet: " + 
                                string(pcap_geterr(handle)));
        }
    #else // TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET
        int sock = get_ether_socket(iface);
        if (!buffer.empty()) {
            #if defined(BSD) || defined(__FreeBSD_kernel__)
            if (::write(sock, &buffer[0], buffer.size()) == -1) {
            #else
            if (::sendto(sock, &buffer[0], buffer.size(), 0, link_addr, len_addr) == -1) {
            #endif
                throw socket_write_error(make_error_string());
            }
        }
    #endif // TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET
}

#endif // !_WIN32 || TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET

#ifndef _WIN32
PDU* PacketSender::recv_l2(PDU& pdu, 
                           struct sockaddr* link_addr, 
                           uint32_t len_addr,
                           const NetworkInterface& iface) {
    int sock = get_ether_socket(iface);
    vector<int> sockets(1, sock);
    return recv_match_loop(sockets, pdu, link_addr, len_addr, false);
}
#endif // _WIN32

PDU* PacketSender::recv_l3(PDU& pdu, 
                           struct sockaddr* link_addr,
                           uint32_t len_addr,
                           SocketType type) {
    open_l3_socket(type);
    vector<int> sockets(1, sockets_[type]);
    if (type == IP_TCP_SOCKET || type == IP_UDP_SOCKET) {
        #ifdef BSD
            throw runtime_error("Receiving L3 packets not supported on this platform");
        #endif
        open_l3_socket(ICMP_SOCKET);
        sockets.push_back(sockets_[ICMP_SOCKET]);
    }
    return recv_match_loop(sockets, pdu, link_addr, len_addr, true);
}

void PacketSender::send_l3(PDU& pdu, 
                           struct sockaddr* link_addr,
                           uint32_t len_addr,
                           SocketType type) {
    open_l3_socket(type);
    int sock = sockets_[type];
    PDU::serialization_type buffer = pdu.serialize();
    const int buf_size = static_cast<int>(buffer.size());
    if (sendto(sock, (const char*)&buffer[0], buf_size, 0, link_addr, len_addr) == -1) {
        throw socket_write_error(make_error_string());
    }
}

PDU* PacketSender::recv_match_loop(const vector<int>& sockets, 
                                   PDU& pdu,
                                   struct sockaddr* link_addr,
                                   uint32_t addrlen,
                                   bool is_layer_3) {
    #ifdef _WIN32
        typedef int socket_len_type;
        typedef int recvfrom_ret_type;
    #else
        typedef socklen_t socket_len_type;
        typedef ssize_t recvfrom_ret_type;
    #endif
    fd_set readfds;
    struct timeval timeout,  end_time;
    int read;
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        bool is_bsd = true;
        // On* BSD, we need to allocate a buffer using the given size.
        const int buffer_size = is_layer_3 ? 2048 : buffer_size_;
        vector<uint8_t> actual_buffer(buffer_size);
        uint8_t* buffer = &actual_buffer[0];
    #else
        bool is_bsd = false;
        uint8_t buffer[2048];
        const int buffer_size = 2048;
    #endif
    
    timeout.tv_sec  = _timeout;
    end_time.tv_sec = static_cast<long>(time(0) + _timeout);
    end_time.tv_usec = timeout.tv_usec = timeout_usec_;
    while (true) {
        FD_ZERO(&readfds);
        int max_fd = 0;
        for (vector<int>::const_iterator it = sockets.begin(); it != sockets.end(); ++it) {
            FD_SET(*it, &readfds);
            max_fd = max(max_fd, *it);
        }
        if ((read = select(max_fd + 1, &readfds, 0, 0, &timeout)) == -1) {
            return 0;
        }
        if (read > 0) {
            for (vector<int>::const_iterator it = sockets.begin(); it != sockets.end(); ++it) {
                if (FD_ISSET(*it, &readfds)) {
                    recvfrom_ret_type size;
                    // Crappy way of only conditionally running this on BSD + layer2
                    if (is_bsd && !is_layer_3) {
                        #if defined(BSD) || defined(__FreeBSD_kernel__)
                        size = ::read(*it, buffer, buffer_size_);
                        const uint8_t* ptr = buffer;
                        // We might see more than one packet
                        while (ptr < (buffer + size)) {
                            const bpf_hdr* bpf_header = reinterpret_cast<const bpf_hdr*>(ptr);
                            const uint8_t* pkt_start = ptr + bpf_header->bh_hdrlen;
                            if (pdu.matches_response(pkt_start, bpf_header->bh_caplen)) {
                                return Internals::pdu_from_flag(pdu.pdu_type(), pkt_start, bpf_header->bh_caplen);
                            }
                            ptr += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
                        }
                        #endif // BSD
                    }
                    else {
                        socket_len_type length = addrlen;
                        size = ::recvfrom(*it, (char*)buffer, buffer_size, 0, link_addr, &length);
                        if (pdu.matches_response(buffer, size)) {
                            return Internals::pdu_from_flag(pdu.pdu_type(), buffer, size);
                        }
                    }
                }
            }
        }
        #if TINS_IS_CXX11
            using namespace std::chrono;
            microseconds end = seconds(end_time.tv_sec) + microseconds(end_time.tv_usec);
            microseconds now = duration_cast<microseconds>(system_clock::now().time_since_epoch());
            if (now > end) {
                return 0;
            }
            // VC complains if we don't statically cast here
            #ifdef _WIN32
                typedef long tv_sec_type;
                typedef long tv_usec_type;
            #else
                typedef time_t tv_sec_type;
                typedef long tv_usec_type;
            #endif
            microseconds diff = end - now;
            timeout.tv_sec = static_cast<tv_sec_type>(duration_cast<seconds>(diff).count());
            timeout.tv_usec = static_cast<tv_usec_type>((diff - seconds(timeout.tv_sec)).count());
        #else
            #ifdef _WIN32
                // Can't do much
                return 0;
            #else
                struct timeval now;
                gettimeofday(&now, 0);
                // If now > end_time
                if (timercmp(&now, &end_time, >)) {
                    return 0;
                }
                struct timeval diff;
                timersub(&end_time, &now, &diff);
                timeout.tv_sec = diff.tv_sec;
                timeout.tv_usec = diff.tv_usec;
            #endif // _WIN32
        #endif // TINS_IS_CXX11
    }
    return 0;
}

int PacketSender::find_type(SocketType type) {
    SocketTypeMap::iterator it = types_.find(type);
    if (it == types_.end()) {
        return -1;
    }
    else {
        return it->second;
    }
}

} // Tins
