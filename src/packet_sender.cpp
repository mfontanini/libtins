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

#include "packet_sender.h"
#ifndef WIN32
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


namespace Tins {
const int PacketSender::INVALID_RAW_SOCKET = -1;
const uint32_t PacketSender::DEFAULT_TIMEOUT = 2;

#ifndef WIN32
    const char *make_error_string() {
        return strerror(errno);
    }
#else
    // fixme
    const char *make_error_string() {
        return "error";
    }
#endif

PacketSender::PacketSender(const NetworkInterface &iface, uint32_t recv_timeout, 
  uint32_t usec) 
: _sockets(SOCKETS_END, INVALID_RAW_SOCKET), 
#if !defined(BSD) && !defined(WIN32) && !defined(__FreeBSD_kernel__)
  _ether_socket(INVALID_RAW_SOCKET),
#endif
  _timeout(recv_timeout), _timeout_usec(usec), default_iface(iface)
{
    _types[IP_TCP_SOCKET] = IPPROTO_TCP;
    _types[IP_UDP_SOCKET] = IPPROTO_UDP;
    _types[IP_RAW_SOCKET] = IPPROTO_RAW;
    _types[IPV6_SOCKET] = IPPROTO_RAW;
    _types[ICMP_SOCKET] = IPPROTO_ICMP;
}

PacketSender::~PacketSender() {
    for(unsigned i(0); i < _sockets.size(); ++i) {
        if(_sockets[i] != INVALID_RAW_SOCKET) 
        #ifndef WIN32
            ::close(_sockets[i]);
        #else
            ::closesocket(_sockets[i]);
        #endif
    }
    #if defined(BSD) || defined(__FreeBSD_kernel__)
    for(BSDEtherSockets::iterator it = _ether_socket.begin(); it != _ether_socket.end(); ++it)
        ::close(it->second);
    #elif !defined(WIN32)
    if(_ether_socket != INVALID_RAW_SOCKET)
        ::close(_ether_socket);
    #endif
}

void PacketSender::default_interface(const NetworkInterface &iface) {
    default_iface = iface;
}

const NetworkInterface& PacketSender::default_interface() const {
    return default_iface;
}

#ifndef WIN32
bool PacketSender::ether_socket_initialized(const NetworkInterface& iface) const {
    #if defined(BSD) || defined(__FreeBSD_kernel__)
    return _ether_socket.count(iface.id());
    #else
    return _ether_socket != INVALID_RAW_SOCKET;
    #endif
}

int PacketSender::get_ether_socket(const NetworkInterface& iface) {
    if(!ether_socket_initialized(iface))
        open_l2_socket(iface);
    #if defined(BSD) || defined(__FreeBSD_kernel__)
    return _ether_socket[iface.id()];
    #else
    return _ether_socket;
    #endif
}

void PacketSender::open_l2_socket(const NetworkInterface& iface) {
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        int sock = -1;
        // At some point, there should be an available device
        for (int i = 0; sock == -1;i++) {
            std::ostringstream oss;
            oss << "/dev/bpf" << i;

            sock = open(oss.str().c_str(), O_RDWR);
        }
        if(sock == -1) 
            throw socket_open_error(make_error_string());
        
        struct ifreq ifr;
        strncpy(ifr.ifr_name, iface.name().c_str(), sizeof(ifr.ifr_name) - 1);
        if(ioctl(sock, BIOCSETIF, (caddr_t)&ifr) < 0) {
            ::close(sock);
            throw socket_open_error(make_error_string());
        }
        // Use immediate mode
        u_int value = 1;
        if(ioctl(sock, BIOCIMMEDIATE, &value) < 0)
            throw socket_open_error(make_error_string());
        // Get the buffer size
        if(ioctl(sock, BIOCGBLEN, &buffer_size) < 0)
            throw socket_open_error(make_error_string());
        _ether_socket[iface.id()] = sock;
    #else
    if (_ether_socket == INVALID_RAW_SOCKET) {
        _ether_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        
        if (_ether_socket == -1)
            throw socket_open_error(make_error_string());
    }
    #endif
}
#endif // WIN32

void PacketSender::open_l3_socket(SocketType type) {
    int socktype = find_type(type);
    if(socktype == -1)
        throw invalid_socket_type();
    if(_sockets[type] == INVALID_RAW_SOCKET) {
        int sockfd;
        sockfd = socket((type == IPV6_SOCKET) ? AF_INET6 : AF_INET, SOCK_RAW, socktype);
        if (sockfd < 0)
            throw socket_open_error(make_error_string());

        const int on = 1;
        #ifndef WIN32
        typedef const void* option_ptr;
        #else
        typedef const char* option_ptr;
        #endif
        setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,(option_ptr)&on,sizeof(on));

        _sockets[type] = sockfd;
    }
}

void PacketSender::close_socket(SocketType type, const NetworkInterface &iface) {
    if(type == ETHER_SOCKET) {
        #if defined(BSD) || defined(__FreeBSD_kernel__)
        BSDEtherSockets::iterator it = _ether_socket.find(iface.id());
        if(it == _ether_socket.end())
            throw invalid_socket_type();
        if(::close(it->second) == -1)
            throw socket_close_error(make_error_string());
        _ether_socket.erase(it);
        #elif !defined(WIN32)
        if(_ether_socket == INVALID_RAW_SOCKET)
            throw invalid_socket_type();
        if(::close(_ether_socket) == -1)
            throw socket_close_error(make_error_string());
        _ether_socket = INVALID_RAW_SOCKET;
        #endif
    }
    else {
        if(type >= SOCKETS_END || _sockets[type] == INVALID_RAW_SOCKET)
            throw invalid_socket_type();
        #ifndef WIN32
        if(close(_sockets[type]) == -1)
            throw socket_close_error(make_error_string());
        #else
        closesocket(_sockets[type]);
        #endif
        _sockets[type] = INVALID_RAW_SOCKET;
    }
}

void PacketSender::send(PDU &pdu) {
    pdu.send(*this, default_iface);
}

void PacketSender::send(PDU &pdu, const NetworkInterface &iface) {
    if (pdu.matches_flag(PDU::ETHERNET_II))
        send<Tins::EthernetII>(pdu, iface);
    #ifdef HAVE_DOT11
        else if (pdu.matches_flag(PDU::DOT11))
            send<Tins::Dot11>(pdu, iface);
        else if (pdu.matches_flag(PDU::RADIOTAP))
            send<Tins::RadioTap>(pdu, iface);
    #endif // HAVE_DOT11
    else if (pdu.matches_flag(PDU::IEEE802_3))
        send<Tins::IEEE802_3>(pdu, iface);
    else send(pdu);
}

PDU *PacketSender::send_recv(PDU &pdu) {
    return send_recv(pdu, default_iface);
}

PDU *PacketSender::send_recv(PDU &pdu, const NetworkInterface &iface) {
    try {
        pdu.send(*this, iface);
    }
    catch(std::runtime_error&) {
        return 0;
    }
    return pdu.recv_response(*this, iface);
}

#ifndef WIN32
void PacketSender::send_l2(PDU &pdu, struct sockaddr* link_addr, 
  uint32_t len_addr, const NetworkInterface &iface) 
{
    int sock = get_ether_socket(iface);
    PDU::serialization_type buffer = pdu.serialize();
    if(!buffer.empty()) {
        #if defined(BSD) || defined(__FreeBSD_kernel__)
        if(::write(sock, &buffer[0], buffer.size()) == -1)
        #else
        if(::sendto(sock, &buffer[0], buffer.size(), 0, link_addr, len_addr) == -1)
        #endif
            throw socket_write_error(make_error_string());
    }
}

PDU *PacketSender::recv_l2(PDU &pdu, struct sockaddr *link_addr, 
  uint32_t len_addr, const NetworkInterface &iface) 
{
    int sock = get_ether_socket(iface);
    std::vector<int> sockets(1, sock);
    return recv_match_loop(sockets, pdu, link_addr, len_addr);
}
#endif // WIN32

PDU *PacketSender::recv_l3(PDU &pdu, struct sockaddr* link_addr, uint32_t len_addr, SocketType type) {
    open_l3_socket(type);
    std::vector<int> sockets(1, _sockets[type]);
    if(type == IP_TCP_SOCKET || type == IP_UDP_SOCKET) {
        #ifdef BSD
            throw std::runtime_error("Receiving L3 packets not supported on this platform");
        #endif
        open_l3_socket(ICMP_SOCKET);
        sockets.push_back(_sockets[ICMP_SOCKET]);
    }
    return recv_match_loop(sockets, pdu, link_addr, len_addr);
}

void PacketSender::send_l3(PDU &pdu, struct sockaddr* link_addr, uint32_t len_addr, SocketType type) {
    open_l3_socket(type);
    int sock = _sockets[type];
    PDU::serialization_type buffer = pdu.serialize();
    if(sendto(sock, (const char*)&buffer[0], buffer.size(), 0, link_addr, len_addr) == -1)
        throw socket_write_error(make_error_string());
}

PDU *PacketSender::recv_match_loop(const std::vector<int>& sockets, PDU &pdu, struct sockaddr* link_addr, uint32_t addrlen) {
    #ifdef WIN32
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
        // On *BSD, we need to allocate a buffer using the given size.
        std::vector<uint8_t> actual_buffer(buffer_size);
        uint8_t *buffer = &actual_buffer[0];
    #else
        uint8_t buffer[2048];
        const int buffer_size = 2048;
    #endif
    
    timeout.tv_sec  = _timeout;
    end_time.tv_sec = time(0) + _timeout;    
    end_time.tv_usec = timeout.tv_usec = _timeout_usec;
    while(true) {
        FD_ZERO(&readfds);
        int max_fd = 0;
        for(std::vector<int>::const_iterator it = sockets.begin(); it != sockets.end(); ++it) {
            FD_SET(*it, &readfds);
            max_fd = std::max(max_fd, *it);
        }
        if((read = select(max_fd + 1, &readfds, 0, 0, &timeout)) == -1)
            return 0;
        if(read > 0) {
            for(std::vector<int>::const_iterator it = sockets.begin(); it != sockets.end(); ++it) {
                if(FD_ISSET(*it, &readfds)) {
                    recvfrom_ret_type size;
                    #if defined(BSD) || defined(__FreeBSD_kernel__)
                        size = ::read(*it, buffer, buffer_size);
                        const uint8_t* ptr = buffer;
                        // We might see more than one packet
                        while(ptr < (buffer + size)) {
                            const bpf_hdr* bpf_header = reinterpret_cast<const bpf_hdr*>(ptr);
                            const uint8_t *pkt_start = ptr + bpf_header->bh_hdrlen;
                            if(pdu.matches_response(pkt_start, bpf_header->bh_caplen)) {
                                return Internals::pdu_from_flag(pdu.pdu_type(), pkt_start, bpf_header->bh_caplen);
                            }
                            ptr += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
                        }
                    #else
                        socket_len_type length = addrlen;
                        size = ::recvfrom(*it, (char*)buffer, buffer_size, 0, link_addr, &length);
                        if(pdu.matches_response(buffer, size)) {
                            return Internals::pdu_from_flag(pdu.pdu_type(), buffer, size);
                        }
                    #endif
                }
            }
        }
        struct timeval this_time, diff;
        #ifdef WIN32
            // fixme
        #else
            gettimeofday(&this_time, 0);
        #endif // WIN32
        if(timeval_subtract(&diff, &end_time, &this_time))
            return 0;
        timeout.tv_sec = diff.tv_sec;
        timeout.tv_usec = diff.tv_usec;
    }
    return 0;
}

int PacketSender::timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y) {
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
    tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

int PacketSender::find_type(SocketType type) {
    SocketTypeMap::iterator it = _types.find(type);
    if(it == _types.end())
        return -1;
    else
        return it->second;
}
}
