#ifndef __PACKET_SENDER_H
#define __PACKET_SENDER_H


#include <vector>
#include <stdint.h>
#include "pdu.h"

namespace Tins {
    class PDU;

    class PacketSender {
    public:
        PacketSender();
        
        /* Opens a socket, using flag as protocol family.
         * Return true if it was possible to open it(or it was already open),
         * false otherwise.  */
        bool open_l3_socket();

        bool close_socket(uint32_t flag);

        bool send(PDU* pdu);

        bool send_l3(PDU *pdu, const struct sockaddr* link_addr, uint32_t len_link_addr);
    private:
        enum SocketType {
            IP_SOCKET,
            SOCKETS_END
        };
        static const int INVALID_RAW_SOCKET = -10;

        std::vector<int> _sockets;
    };
};

#endif
