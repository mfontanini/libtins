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

#ifndef WIN32
    #include <netinet/in.h>
#endif

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
        /** \brief The default timeout for receive actions.
         */
        static const uint32_t DEFAULT_TIMEOUT;
    
        /** \brief Flags to indicate the socket type.
         */
        enum SocketType {
            ETHER_SOCKET,
            IP_SOCKET,
            ARP_SOCKET,
            ICMP_SOCKET,
            SOCKETS_END
        };

        /**
         * \brief Constructor for PacketSender objects.
         * 
         * \param recv_timeout The timeout which will be used when receiving responses.
         */
        PacketSender(uint32_t recv_timeout = DEFAULT_TIMEOUT);
        
        /** \brief PacketSender destructor.
         * 
         * This gracefully closes all open sockets.
         */
        ~PacketSender();

        /** \brief Opens a layer y socket.
         * 
         * \return Returns true if the socket was open successfully, false otherwise.
         */
        bool open_l2_socket();

        /** \brief Opens a layer 3 socket, using the corresponding protocol
         * for the given flag.
         * 
         * \param type The type of socket which will be used to pick the protocol flag
         * for this socket.
         * \return Returns true if the socket was open successfully, false otherwise.
         */
        bool open_l3_socket(SocketType type);

        /** \brief Closes the socket associated with the given flag.
         * 
         * \param flag
         * \return Returns true if the socket was closed successfully, false otherwise.
         */
        bool close_socket(uint32_t flag);

        /** \brief Sends a PDU. 
         * 
         * This method is used to send PDUs. It opens the required socket(if it's not open yet).
         * 
         * \param pdu The PDU to send.
         * \return Returns true if the PDU is sent successfully, false otherwise.
         */
        bool send(PDU* pdu);

        /** \brief Sends a PDU and waits for its response. 
         * 
         * This method is used to send PDUs and receive their response. 
         * It opens the required socket(if it's not open yet). This can be used
         * to expect responses for ICMP, ARP, and such packets that are normally
         * answered by the host that receives the packet.
         * 
         * \param pdu The PDU to send.
         * \return Returns the response PDU, 0 if not response was received.
         */
        PDU *send_recv(PDU *pdu);

        /** \brief Receives a layer 2 PDU response to a previously sent PDU.
         * 
         * This PacketSender will receive data from a raw socket, open using the corresponding flag,
         * according to the given type of protocol, until a match for the given PDU is received. 
         * 
         * \param pdu The PDU which will try to match the responses.
         * \param link_addr The sockaddr struct which will be used to receive the PDU.
         * \param len_addr The sockaddr struct length.
         * \return Returns the response PDU. If no response is received, then 0 is returned.
         */
        PDU *recv_l2(PDU *pdu, struct sockaddr *link_addr, uint32_t len_addr);

        /** \brief Sends a level 2 PDU.
         * 
         * This method sends a layer 2 PDU, using a raw socket, open using the corresponding flag,
         * according to the given type of protocol. 
         * 
         * \param pdu The PDU to send.
         * \param link_addr The sockaddr struct which will be used to send the PDU.
         * \param len_addr The sockaddr struct length.
         * \return Returns true if the PDU was successfully sent, false otherwise.
         */
        bool send_l2(PDU *pdu, struct sockaddr* link_addr, uint32_t len_addr);

        /** \brief Receives a layer 3 PDU response to a previously sent PDU.
         * 
         * This PacketSender will receive data from a raw socket, open using the corresponding flag,
         * according to the given type of protocol, until a match for the given PDU is received. 
         * 
         * \param pdu The PDU which will try to match the responses.
         * \param link_addr The sockaddr struct which will be used to receive the PDU.
         * \param len_addr The sockaddr struct length.
         * \param type The socket protocol type.
         * \return Returns the response PDU. If no response is received, then 0 is returned.
         */
        PDU *recv_l3(PDU *pdu, struct sockaddr *link_addr, uint32_t len_addr, SocketType type);

        /** \brief Sends a level 3 PDU.
         * 
         * This method sends a layer 3 PDU, using a raw socket, open using the corresponding flag,
         * according to the given type of protocol.
         * 
         * \param pdu The PDU to send.
         * \param link_addr The sockaddr struct which will be used to send the PDU.
         * \param len_addr The sockaddr struct length.
         * \param type The socket protocol type.
         * \return Returns true if the PDU was successfully sent, false otherwise.
         */
        bool send_l3(PDU *pdu, struct sockaddr *link_addr, uint32_t len_addr, SocketType type);
    private:
        static const int INVALID_RAW_SOCKET;

        typedef std::map<SocketType, int> SocketTypeMap;

        int find_type(SocketType type);
        
        PDU *recv_match_loop(int sock, PDU *pdu, struct sockaddr* link_addr, socklen_t addrlen);

        std::vector<int> _sockets;
        SocketTypeMap _types;
        uint32_t _timeout;
    };
};

#endif
