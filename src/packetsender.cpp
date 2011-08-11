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
        delete[] buffer;
    }

    return ret_val;

}
