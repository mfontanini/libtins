/*
 * Copyright (c) 2014, Matias Fontanini
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
#include "cxxstd.h"

struct timeval;
struct sockaddr;

namespace Tins {
    class PDU;
    
    /**
     * \class PacketSender
     * \brief Sends packets through a network interface.
     *
     * This class allows sending packets through a network interface.
     * It can send basically two types of packets:
     *
     * - Those that contain a link layer PDU (EthernetII, SLL, etc). These
     * will be serialized and sent through an interface that has to be 
     * specified. This can be done by providing it when you call 
     * PacketSender::send, or set a default one using 
     * PacketSender::default_interface.
     * - Those that don't contain a link layer PDU. In this case, the 
     * kernel will be responsible for picking the appropriate network interface
     * based on the destination address.
     *
     * Sending packets can be done via PacketSender::send:
     *
     * \code
     * // Construct a packet which uses an EthernetII link layer.
     * EthernetII pkt1 = ...;
     *
     * // Construct a packet sender, which we'll use to send packets.
     * PacketSender sender;
     * 
     * // Send it through interface eth0
     * sender.send(pkt1, "eth0");
     *
     * // Set the default interface to eth0
     * sender.default_interface("eth0");
     * 
     * // This is now equivalent to the previous send.
     * sender.send(pkt1);
     *
     * // Construct a packet which has no link layer protocol.
     * IP ip = IP("192.168.0.1") / TCP(22, 928);
     *
     * // Here the kernel will figure out which interface to use and it will
     * // append the appropriate link layer protocol PDU. It will also perform
     * // the necessary ARP lookups in order to use the destination host's
     * // hardware address.
     * //
     * // libtins will find which is the appropriate source IP address to use.
     * // This will be done by the kernel as well, but it's required when 
     * // calculating checksums.
     * sender.send(ip);
     * \endcode
     *
     * PacketSender also supports sending a packet and waiting for a response.
     * This can be done by using PacketSender::send_recv.
     *
     * This class opens sockets as it needs to, and closes them when the object
     * is destructed.
     *
     * \sa PacketSender::send
     * \sa PacketSender::send_recv
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
            IP_TCP_SOCKET,
            IP_UDP_SOCKET,
            IP_RAW_SOCKET,
            ARP_SOCKET,
            ICMP_SOCKET,
            IPV6_SOCKET,
            SOCKETS_END
        };

        /**
         * \brief Constructor for PacketSender objects.
         * 
         * \param iface The default interface in which to send the packets.
         * \param recv_timeout The timeout which will be used when receiving responses.
         */
        PacketSender(const NetworkInterface &iface = NetworkInterface(), 
          uint32_t recv_timeout = DEFAULT_TIMEOUT, uint32_t usec = 0);
        
        #if TINS_IS_CXX11
            /**
             * \brief Move constructor.
             * \param rhs The sender to be moved.
             */
            PacketSender(PacketSender &&rhs) TINS_NOEXCEPT {
                *this = std::move(rhs);
            }
            
            /**
             * \brief Move assignment operator.
             * \param rhs The sender to be moved.
             */
            PacketSender& operator=(PacketSender &&rhs) TINS_NOEXCEPT {
                _sockets = std::move(rhs._sockets);
                rhs._sockets = std::vector<int>(SOCKETS_END, INVALID_RAW_SOCKET);
                #ifndef WIN32
                    #if defined(BSD) || defined(__FreeBSD_kernel__)
                    _ether_socket = std::move(rhs._ether_socket);
                    #else
                    _ether_socket = rhs._ether_socket;
                    rhs._ether_socket = INVALID_RAW_SOCKET;
                    #endif
                #endif
                _types = rhs._types; // no move
                _timeout = rhs._timeout;
                _timeout_usec = rhs._timeout_usec;
                default_iface = rhs.default_iface;
                return *this;
            }
        #endif
        
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
         * If this operation fails, then a socket_open_error will be thrown.
         */
        void open_l2_socket(const NetworkInterface& iface = NetworkInterface());
        #endif // WIN32

        /** 
         * \brief Opens a layer 3 socket, using the corresponding protocol
         * for the given flag.
         * 
         * If this operation fails, then a socket_open_error will be thrown.
         * If the provided socket type is not valid, an invalid_socket_type
         * exception will be throw.
         * 
         * \param type The type of socket which will be used to pick the protocol flag
         * for this socket.
         */
        void open_l3_socket(SocketType type);

        /** 
         * \brief Closes the socket associated with the given flag.
         * 
         * If the provided type is invalid, meaning no such open socket
         * exists, an invalid_socket_type exception is thrown.
         * 
         * If any socket close errors are encountered, a socket_close_error
         * is thrown.
         * 
         * \param type The type of the socket to be closed.
         */
        void close_socket(SocketType type, const NetworkInterface &iface = NetworkInterface());

        /**
         * \brief Sets the default interface.
         * 
         * The interface will be used whenever PacketSender::send(PDU&) 
         * is called.
         */
        void default_interface(const NetworkInterface &iface);
        
        /**
         * \brief Gets the default interface.
         * 
         * \sa PacketSender::default_interface
         */
        const NetworkInterface& default_interface() const;

        /** 
         * \brief Sends a PDU. 
         * 
         * This method opens the appropriate socket, if it's not open yet, 
         * and sends the PDU on the open socket.
         * 
         * If any send error occurs, then a socket_write_error is thrown.
         * 
         * If the PDU contains a link layer protocol, then default_interface
         * is used.
         * 
         * \sa PacketSender::default_interface
         * 
         * \param pdu The PDU to be sent.
         */
        void send(PDU &pdu);
        
        /** 
         * \brief Sends a PDU. 
         * 
         * \sa PacketSender::send
         * 
         * This overload takes a NetworkInterface. The packet is sent
         * through that interface if a link-layer PDU is present, 
         * otherwise this call is equivalent to send(PDU&).
         * 
         * The interface stored in the link layer PDU(if any), is restored
         * after this method ends.
         * 
         * \param pdu The PDU to be sent.
         * \param iface The network interface to use.
         */
        void send(PDU &pdu, const NetworkInterface &iface);

        /** 
         * \brief Sends a PDU and waits for its response. 
         * 
         * This method is used to send PDUs and receive their response. 
         * The packet is sent, and then a response is awaited. 
         * PDU::matches_pdu is called on the packet sent in order to
         * check whether a packet received is a response. 
         *
         * This will match every response to a packet. For example,
         * if you send a TCP packet, any response matching the same
         * IP addresses and ports will be taken as a response to it.
         * This also happens for other protocols, such as ARP, ICMP, 
         * DHCP, DNS, IP, etc.
         *
         * If you send a packet and get an ICMP response indicating
         * an error (such as host unreachable, ttl exceeded, etc),
         * that packet will be considered a response.
         * 
         * \param pdu The PDU to send.
         * \return Returns the response PDU, 0 if not response was received.
         */
        PDU *send_recv(PDU &pdu);
        
        /** 
         * \brief Sends a PDU and waits for its response. 
         *
         * Sends a packet and receives a response. This overload takes 
         * a NetworkInterface. 
         * 
         * \sa PacketSender::send_recv(PDU&);
         * \param pdu The PDU to send.
         * \param iface The network interface in which to send and receive.
         * \return Returns the response PDU, 0 if not response was received.
         */
        PDU *send_recv(PDU &pdu, const NetworkInterface &iface);

        #ifndef WIN32
        /** 
         * \brief Receives a layer 2 PDU response to a previously sent PDU.
         *
         * This method is used internally. You should just use PacketSender::send_recv.
         * 
         * This PacketSender will receive data from a raw socket, open using 
         * the corresponding flag, according to the given type of protocol, until 
         * a match for the given PDU is received. 
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
         * This method is used internally. You should just use PacketSender::send.
         * 
         * This method sends a layer 2 PDU, using a raw socket, open 
         * using the corresponding flag, according to the given type of 
         * protocol. 
         * 
         * If any socket write error occurs, a socket_write_error is thrown.
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
         * This method is used internally. You should just use PacketSender::send_recv.
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
         * This method is used internally. You should just use PacketSender::send.
         * 
         * This method sends a layer 3 PDU, using a raw socket, open using the corresponding flag,
         * according to the given type of protocol.
         * 
         * If any socket write error occurs, a socket_write_error is thrown.
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

        PacketSender(const PacketSender&);
        PacketSender& operator=(const PacketSender&);
        int find_type(SocketType type);
        int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y);
        #ifndef WIN32
            bool ether_socket_initialized(const NetworkInterface& iface = NetworkInterface()) const;
            int get_ether_socket(const NetworkInterface& iface = NetworkInterface());
        #endif
        template<typename T>
        void send(PDU &pdu, const NetworkInterface &iface) {
            static_cast<T&>(pdu).send(*this, iface);
        }
        
        PDU *recv_match_loop(const std::vector<int>& sockets, PDU &pdu, struct sockaddr* link_addr, 
            uint32_t addrlen);

        std::vector<int> _sockets;
        #ifndef WIN32
            #if defined(BSD) || defined(__FreeBSD_kernel__)
            typedef std::map<uint32_t, int> BSDEtherSockets;
            BSDEtherSockets _ether_socket;
            #else
            int _ether_socket;
            #endif
        #endif
        SocketTypeMap _types;
        uint32_t _timeout, _timeout_usec;
        NetworkInterface default_iface;
        // In BSD we need to store the buffer size, retrieved using BIOCGBLEN
        #if defined(BSD) || defined(__FreeBSD_kernel__)
        int buffer_size;
        #endif
    };
}

#endif // TINS_PACKET_SENDER_H
