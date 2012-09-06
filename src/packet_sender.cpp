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
#endif
#include <cassert>
#include <errno.h>
#include <cstring>
#include <ctime>
#include "pdu.h"
#include "packet_sender.h"


const int Tins::PacketSender::INVALID_RAW_SOCKET = -1;
const uint32_t Tins::PacketSender::DEFAULT_TIMEOUT = 2;

Tins::PacketSender::PacketSender(uint32_t recv_timeout, uint32_t usec) : 
    _sockets(SOCKETS_END, INVALID_RAW_SOCKET), _timeout(recv_timeout), _timeout_usec(usec) {
    _types[IP_SOCKET] = IPPROTO_RAW;
    _types[ICMP_SOCKET] = IPPROTO_ICMP;
}

Tins::PacketSender::~PacketSender() {
    for(unsigned i(0); i < _sockets.size(); ++i) {
        if(_sockets[i] != INVALID_RAW_SOCKET)
            ::close(_sockets[i]);
    }
}

bool Tins::PacketSender::open_l2_socket() {
    if (_sockets[ETHER_SOCKET] != INVALID_RAW_SOCKET)
        return true;
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1)
        return false;
    _sockets[ETHER_SOCKET] = sock;
    return true;
}

bool Tins::PacketSender::open_l3_socket(SocketType type) {
    int socktype = find_type(type);
    if(socktype == -1)
        return false;
    if(_sockets[type] != INVALID_RAW_SOCKET)
        return true;
    int sockfd;
    sockfd = socket(AF_INET, SOCK_RAW, socktype);
    if (sockfd < 0)
        return false;

    const int on = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,(const void *)&on,sizeof(on));

    _sockets[type] = sockfd;
    return true;
}

bool Tins::PacketSender::close_socket(uint32_t flag) {
    if(flag >= SOCKETS_END || _sockets[flag] == INVALID_RAW_SOCKET)
        return false;
    close(_sockets[flag]);
    _sockets[flag] = INVALID_RAW_SOCKET;
    return true;
}

bool Tins::PacketSender::send(PDU *pdu) {
    return pdu->send(this);
}

Tins::PDU *Tins::PacketSender::send_recv(PDU *pdu) {
    if(!pdu->send(this))
        return 0;
    return pdu->recv_response(this);
}

bool Tins::PacketSender::send_l2(PDU *pdu, struct sockaddr* link_addr, uint32_t len_addr) {
    if(!open_l2_socket())
        return false;

    int sock = _sockets[ETHER_SOCKET];
    PDU::serialization_type buffer = pdu->serialize();
    if(buffer.size() == 0)
        return false;
    bool ret_val = (sendto(sock, &buffer[0], buffer.size(), 0, link_addr, len_addr) != -1);

    return ret_val;
}

Tins::PDU *Tins::PacketSender::recv_l2(PDU *pdu, struct sockaddr *link_addr, uint32_t len_addr) {
    if(!open_l2_socket())
        return 0;
    return recv_match_loop(_sockets[ETHER_SOCKET], pdu, link_addr, len_addr);
}

Tins::PDU *Tins::PacketSender::recv_l3(PDU *pdu, struct sockaddr* link_addr, uint32_t len_addr, SocketType type) {
    if(!open_l3_socket(type))
        return 0;
    return recv_match_loop(_sockets[type], pdu, link_addr, len_addr);
}

bool Tins::PacketSender::send_l3(PDU *pdu, struct sockaddr* link_addr, uint32_t len_addr, SocketType type) {
    bool ret_val = true;
    if(!open_l3_socket(type))
        ret_val = false;
    if (ret_val) {
        int sock = _sockets[type];
        PDU::serialization_type buffer = pdu->serialize();
        ret_val = (sendto(sock, &buffer[0], buffer.size(), 0, link_addr, len_addr) != -1);
    }
    return ret_val;
}

Tins::PDU *Tins::PacketSender::recv_match_loop(int sock, PDU *pdu, struct sockaddr* link_addr, uint32_t addrlen) {
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
            ssize_t size = recvfrom(sock, buffer, 2048, 0, link_addr, &addrlen);
            if(pdu->matches_response(buffer, size)) {
                return pdu->clone_packet(buffer, size);
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

int Tins::PacketSender::timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y) {
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

int Tins::PacketSender::find_type(SocketType type) {
    SocketTypeMap::iterator it = _types.find(type);
    if(it == _types.end())
        return -1;
    else
        return it->second;
}
