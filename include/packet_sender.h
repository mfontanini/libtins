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

#ifndef TINS_PACKET_SENDER_H
#define TINS_PACKET_SENDER_H


#include <string>
#include <stdexcept>
#include <vector>
#include <stdint.h>
#include <map>
#include "network_interface.h"
#include "macros.h"

struct timeval;
struct sockaddr;

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
        /** 
         * The default timeout for receive actions.
         */
        static const uint32_t DEFAULT_TIMEOUT;
    
        /** 
         * Flags to indicate the socket type.
         */
        enum SocketType {
            ETHER_SOCKET,
            IP_SOCKET,
            ARP_SOCKET,
            ICMP_SOCKET,
            IPV6_SOCKET,
            SOCKETS_END
        };

        /**
         * \brief Constructor for PacketSender objects.
         * 
         * \param recv_timeout The timeout which will be used when receiving responses.
         */
        PacketSender(uint32_t recv_timeout = DEFAULT_TIMEOUT, uint32_t usec = 0);
        
        /** 
         * \brief PacketSender destructor.
         * 
         * This gracefully closes all open sockets.
         */
        ~PacketSender();

        #ifndef WIN32
        /** 
         * \brief Opens a layer 2 socket.
         * 
         * If this operation fails, then a SocketOpenError will be thrown.
         */
        void open_l2_socket(const NetworkInterface& iface = NetworkInterface());
        #endif // WIN32

        /** 
         * \brief Opens a layer 3 socket, using the corresponding protocol
         * for the given flag.
         * 
         * If this operation fails, then a SocketOpenError will be thrown.
         * If the provided socket type is not valid, a InvalidSocketTypeError
         * will be throw.
         * 
         * \param type The type of socket which will be used to pick the protocol flag
         * for this socket.
         */
        void open_l3_socket(SocketType type);

        /** 
         * \brief Closes the socket associated with the given flag.
         * 
         * If the provided type is invalid, meaning no such open socket
         * exists, a InvalidSocketTypeError is thrown.
         * 
         * If any socket close errors are encountered, a SocketCloseError
         * is thrown.
         * 
         * \param type The type of the socket to be closed.
         */
        void close_socket(SocketType type, const NetworkInterface &iface = NetworkInterface());

        /** 
         * \brief Sends a PDU. 
         * 
         * This method opens the appropriate socket, if it's not open yet, 
         * and sends the PDU on the open socket.
         * 
         * If any send error occurs, then a SocketWriteError is thrown.
         * 
         * \param pdu The PDU to be sent.
         */
        void send(PDU &pdu);

        /** 
         * \brief Sends a PDU and waits for its response. 
         * 
         * This method is used to send PDUs and receive their response. 
         * It opens the required socket(if it's not open yet). This can be used
         * to expect responses for ICMP, ARP, and such packets that are normally
         * answered by the host that receives the packet.
         * 
         * \param pdu The PDU to send.
         * \return Returns the response PDU, 0 if not response was received.
         */
        PDU *send_recv(PDU &pdu);

        #ifndef WIN32
        /** 
         * \brief Receives a layer 2 PDU response to a previously sent PDU.
         * 
         * This PacketSender will receive data from a raw socket, open using the corresponding flag,
         * according to the given type of protocol, until a match for the given PDU is received. 
         * 
         * \param pdu The PDU which will try to match the responses.
         * \param link_addr The sockaddr struct which will be used to receive the PDU.
         * \param len_addr The sockaddr struct length.
         * \return Returns the response PDU. If no response is received, then 0 is returned.
         */
        PDU *recv_l2(PDU &pdu, struct sockaddr *link_addr, uint32_t len_addr,
          const NetworkInterface &iface = NetworkInterface());

        /** 
         * \brief Sends a level 2 PDU.
         * 
         * This method sends a layer 2 PDU, using a raw socket, open 
         * using the corresponding flag, according to the given type of 
         * protocol. 
         * 
         * If any socket write error occurs, a SocketWriteError is thrown.
         * 
         * \param pdu The PDU to send.
         * \param link_addr The sockaddr struct which will be used to send the PDU.
         * \param len_addr The sockaddr struct length.
         */
        void send_l2(PDU &pdu, struct sockaddr* link_addr, uint32_t len_addr, 
          const NetworkInterface &iface = NetworkInterface());
        #endif // WIN32

        /** 
         * \brief Receives a layer 3 PDU response to a previously sent PDU.
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
        PDU *recv_l3(PDU &pdu, struct sockaddr *link_addr, uint32_t len_addr, SocketType type);

        /** 
         * \brief Sends a level 3 PDU.
         * 
         * This method sends a layer 3 PDU, using a raw socket, open using the corresponding flag,
         * according to the given type of protocol.
         * 
         * If any socket write error occurs, a SocketWriteError is thrown.
         * 
         * \param pdu The PDU to send.
         * \param link_addr The sockaddr struct which will be used to send the PDU.
         * \param len_addr The sockaddr struct length.
         * \param type The socket protocol type.
         */
        void send_l3(PDU &pdu, struct sockaddr *link_addr, uint32_t len_addr, SocketType type);
    private:
        static const int INVALID_RAW_SOCKET;

        typedef std::map<SocketType, int> SocketTypeMap;

        int find_type(SocketType type);
        int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y);
        #ifndef WIN32
        bool ether_socket_initialized(const NetworkInterface& iface = NetworkInterface()) const;
        int get_ether_socket(const NetworkInterface& iface = NetworkInterface());
        #endif
        
        PDU *recv_match_loop(int sock, PDU &pdu, struct sockaddr* link_addr, uint32_t addrlen);

        std::vector<int> _sockets;
        #ifndef WIN32
            #ifdef BSD
            typedef std::map<uint32_t, int> BSDEtherSockets;
            BSDEtherSockets _ether_socket;
            #else
            int _ether_socket;
            #endif
        #endif
        SocketTypeMap _types;
        uint32_t _timeout, _timeout_usec;
    };
    
    
    class SocketOpenError : public std::runtime_error {
    public:
        SocketOpenError(const std::string &msg) 
        : std::runtime_error(msg) { }
    };
    
    class SocketCloseError : public std::runtime_error {
    public:
        SocketCloseError(const std::string &msg) 
        : std::runtime_error(msg) { }
    };
    
    class SocketWriteError : public std::runtime_error {
    public:
        SocketWriteError(const std::string &msg) 
        : std::runtime_error(msg) { }
    };
    
    class InvalidSocketTypeError : public std::exception {
    public:
        const char *what() const throw() {
            return "The provided socket type is invalid";
        }
    };
}

#endif // TINS_PACKET_SENDER_H
