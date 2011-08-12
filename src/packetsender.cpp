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
    #include <arpa/inet.h>
    #include <unistd.h>
    #include </usr/include/linux/if_ether.h>
    #include </usr/include/linux/if_packet.h>
    #include <netdb.h>
#endif
#include <assert.h>
#include <iostream>
#include <errno.h>
#include <string.h>
#include "packetsender.h"


const int Tins::PacketSender::INVALID_RAW_SOCKET = -10;

Tins::PacketSender::PacketSender() : _sockets(SOCKETS_END, INVALID_RAW_SOCKET) {

}

bool Tins::PacketSender::open_l3_socket() {
    if(_sockets[IP_SOCKET] != INVALID_RAW_SOCKET)
        return true;
    int sockfd;
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0)
        return false;

    const int on = 1;
    setsockopt(sockfd, IPPROTO_IP,IP_HDRINCL,(const void *)&on,sizeof(on));

    _sockets[IP_SOCKET] = sockfd;
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

bool Tins::PacketSender::send_l3(PDU *pdu, const struct sockaddr* link_addr, uint32_t len_link_addr) {
    bool ret_val = true;
    if(!open_l3_socket())
        ret_val = false;
    if (ret_val) {
        uint32_t sz;
        int sock = _sockets[IP_SOCKET];
        uint8_t *buffer = pdu->serialize(sz);
        ret_val = (sendto(sock, buffer, sz, 0, link_addr, len_link_addr) != -1);
        std::cout << "Ret_val: " << ret_val << "\n";
        delete[] buffer;
    }

    return ret_val;

}
