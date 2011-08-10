#ifndef WIN32
    #include <sys/socket.h>
	#include <sys/select.h>
	#include <arpa/inet.h>
    #include <unistd.h>
    #include </usr/include/linux/if_ether.h>
    #include </usr/include/linux/if_packet.h>
#endif
#include <assert.h>
#include <iostream>
#include <errno.h>
#include <string.h>
#include "packetsender.h"


bool Tins::PacketSender::open_socket(uint32_t flag) {
    if(_sockets.find(flag) != _sockets.end())
        return true;
    int sockfd;
    sockfd = socket(PF_PACKET, SOCK_RAW, 255);
    if (sockfd < 0) {
        std::cout << "Flag: " << flag << "\n";
        std::cout << "Errno: " << errno << "\n";
        return false;
    }
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
        sa.sll_family = AF_PACKET;
        sa.sll_protocol = htons(ETH_P_IP);
        sa.sll_ifindex = 1;                         
        sa.sll_hatype = 1;
        sa.sll_pkttype = PACKET_BROADCAST;
        sa.sll_halen = 0;
        sa.sll_addr[2] = 0xde;
    if(bind(sockfd, (struct sockaddr *)&sa, sizeof(sockaddr_ll)) != 0) {
        std::cout << "Error: " << errno << "\n";
        return false;
    }
  /*  {				
        int one = 1;
        const int *val = &one;
        if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
          std::cout << "Warning: Cannot set HDRINCL!\n";
      }*/
    _sockets[flag] = sockfd;
    return true;
}

bool Tins::PacketSender::close_socket(uint32_t flag) {
    SocketMap::iterator it = _sockets.find(flag);
    if(it == _sockets.end())
        return false;
    close(it->second);
    _sockets.erase(it);
    return true;
}

bool Tins::PacketSender::write(int sock, uint8_t *buffer, uint32_t size) {
	uint32_t index = 0;
    int ret;
	while(size) {
		if((ret = ::send(sock, &buffer[index], size, 0)) <= 0) {
            std::cout << errno << "\n";
            return false;
        }
		index += ret;
		size -= ret;
	}
    /*if(!sendto(sock, buffer, size, 0,
                      const struct sockaddr *dest_addr, socklen_t addrlen);))*/
	return true;
}

bool Tins::PacketSender::send(PDU *pdu) {
    uint32_t sz, flag(pdu->flag());
    uint8_t *buffer = pdu->serialize(sz);
    bool ret_val = true;
    if(!open_socket(flag) || !write(_sockets[flag], buffer, sz))
        ret_val = false;
    delete[] buffer;
    return ret_val;
}
