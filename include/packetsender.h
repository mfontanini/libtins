#ifndef __PACKET_SENDER_H
#define __PACKET_SENDER_H


#include <map>
#include <stdint.h>
#include "pdu.h"

namespace Tins {

    class PacketSender {
    public:
        /* Opens a socket, using flag as protocol family. 
         * Return true if it was possible to open it(or it was already open),
         * false otherwise.  */
        bool open_socket(uint32_t flag);
        
        bool close_socket(uint32_t flag);
        
        bool send(PDU *pdu);
    private:
        typedef std::map<uint32_t, int> SocketMap;
        bool write(int sock, uint8_t *buffer, uint32_t size);
        
        SocketMap _sockets;
    };
};

#endif
