#ifndef __PACKET_SENDER_H
#define __PACKET_SENDER_H


#include <map>
#include <stdint.h>
#include "pdu.h"

namespace Tins {
    class PDU;

    class PacketSender {
    public:
        /* Opens a socket, using flag as protocol family.
         * Return true if it was possible to open it(or it was already open),
         * false otherwise.  */
        bool open_l3_socket();

        bool close_socket(uint32_t flag);

        bool send(PDU* pdu);

        bool send_l3(PDU *pdu, const struct sockaddr* link_addr, uint32_t len_link_addr);
    private:
        typedef std::map<uint32_t, int> SocketMap;

        static const uint32_t IP_SOCKET;

        SocketMap _sockets;
    };
};

#endif
