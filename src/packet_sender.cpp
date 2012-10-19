/*
 * Copyright (c) 2012, Nasel
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

#ifndef WIN32
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <linux/if_ether.h>
    #include <linux/if_packet.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <errno.h>
#else
    #include <winsock2.h>
    #include <ws2tcpip.h>
#endif
#include <cassert>
#include <cstring>
#include <ctime>
#include "pdu.h"
#include "packet_sender.h"


namespace Tins {
const int PacketSender::INVALID_RAW_SOCKET = -1;
const uint32_t PacketSender::DEFAULT_TIMEOUT = 2;

#ifndef WIN32
    const char *make_error_string() {
        return strerror(errno);
    }
#else

#endif

PacketSender::PacketSender(uint32_t recv_timeout, uint32_t usec) : 
  _sockets(SOCKETS_END, INVALID_RAW_SOCKET), _timeout(recv_timeout), 
  _timeout_usec(usec)
{
    _types[IP_SOCKET] = IPPROTO_RAW;
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
}

#ifndef WIN32
void PacketSender::open_l2_socket() {
    if (_sockets[ETHER_SOCKET] == INVALID_RAW_SOCKET) {
        int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock == -1)
            throw SocketOpenError(make_error_string());
        _sockets[ETHER_SOCKET] = sock;
    }
}
#endif // WIN32

void PacketSender::open_l3_socket(SocketType type) {
    int socktype = find_type(type);
    if(socktype == -1)
        throw InvalidSocketTypeError();
    if(_sockets[type] == INVALID_RAW_SOCKET) {
        int sockfd;
        sockfd = socket(AF_INET, SOCK_RAW, socktype);
        if (sockfd < 0)
            throw SocketOpenError(make_error_string());

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

void PacketSender::close_socket(SocketType type) {
    if(type >= SOCKETS_END || _sockets[type] == INVALID_RAW_SOCKET)
        throw InvalidSocketTypeError();
    #ifndef WIN32
    if(close(_sockets[type]) == -1)
        throw SocketCloseError(make_error_string());
    #else
    closesocket(_sockets[type]);
    #endif
    _sockets[type] = INVALID_RAW_SOCKET;
}

void PacketSender::send(PDU &pdu) {
    pdu.send(*this);
}

PDU *PacketSender::send_recv(PDU &pdu) {
    try {
        pdu.send(*this);
    }
    catch(std::runtime_error&) {
        return 0;
    }
    return pdu.recv_response(*this);
}
#ifndef WIN32
void PacketSender::send_l2(PDU &pdu, struct sockaddr* link_addr, uint32_t len_addr) {
    open_l2_socket();

    int sock = _sockets[ETHER_SOCKET];
    PDU::serialization_type buffer = pdu.serialize();
    if(!buffer.empty()) {
        if(sendto(sock, &buffer[0], buffer.size(), 0, link_addr, len_addr) == -1)
            throw SocketWriteError(make_error_string());
    }
}

PDU *PacketSender::recv_l2(PDU &pdu, struct sockaddr *link_addr, uint32_t len_addr) {
    open_l2_socket();
    return recv_match_loop(_sockets[ETHER_SOCKET], pdu, link_addr, len_addr);
}
#endif // WIN32

PDU *PacketSender::recv_l3(PDU &pdu, struct sockaddr* link_addr, uint32_t len_addr, SocketType type) {
    open_l3_socket(type);
    return recv_match_loop(_sockets[type], pdu, link_addr, len_addr);
}

void PacketSender::send_l3(PDU &pdu, struct sockaddr* link_addr, uint32_t len_addr, SocketType type) {
    open_l3_socket(type);
    int sock = _sockets[type];
    PDU::serialization_type buffer = pdu.serialize();
    if(sendto(sock, (const char*)&buffer[0], buffer.size(), 0, link_addr, len_addr) == -1)
        throw SocketWriteError(make_error_string());
}

PDU *PacketSender::recv_match_loop(int sock, PDU &pdu, struct sockaddr* link_addr, uint32_t addrlen) {
    fd_set readfds;
    struct timeval timeout,  end_time;
    int read;
    uint8_t buffer[2048];
    timeout.tv_sec  = _timeout;
    end_time.tv_sec = time(0) + _timeout;    
    end_time.tv_usec = timeout.tv_usec = _timeout_usec;
    while(true) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        if((read = select(sock + 1, &readfds, 0, 0, &timeout)) == -1) {
            return 0;
        }
        if(FD_ISSET(sock, &readfds)) {
            ssize_t size = recvfrom(sock, (char*)buffer, 2048, 0, link_addr, &addrlen);
            if(pdu.matches_response(buffer, size)) {
                return pdu.clone_packet(buffer, size);
            }
        }
        struct timeval this_time, diff;
        gettimeofday(&this_time, 0);
        if(timeval_subtract(&diff, &end_time, &this_time)) {
            return 0;
        }
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
