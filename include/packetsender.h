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

#ifndef __PACKET_SENDER_H
#define __PACKET_SENDER_H


#include <vector>
#include <stdint.h>
#include <map>
#include "pdu.h"

namespace Tins {
    class PDU;

    /**
     * \brief Class that enables sending the created PDUs
     *
     * PacketSender class is responsible for sending the packets using the
     * correct PDU layer. It is responsible for opening the raw sockets.
     */
    class PacketSender {
    public:
        enum SocketType {
            IP_SOCKET,
            ICMP_SOCKET,
            SOCKETS_END
        };
    
        /**
         * \brief Constructor for PacketSender objects.
         */
        PacketSender();


        bool open_l2_socket();

        bool open_l3_socket(SocketType type);

        bool close_socket(uint32_t flag);

        bool send(PDU* pdu);
        
        PDU *send_recv(PDU *pdu);

        bool send_l2(PDU *pdu);
        
        PDU *recv_l3(PDU *pdu, struct sockaddr *link_addr, uint32_t len_link_addr, SocketType type);

        bool send_l3(PDU *pdu, struct sockaddr *link_addr, uint32_t len_link_addr, SocketType type);
    private:
        static const int INVALID_RAW_SOCKET;
        
        typedef std::map<SocketType, int> SocketTypeMap;
        
        int find_type(SocketType type);

        std::vector<int> _sockets;
        SocketTypeMap _types;
    };
};

#endif
