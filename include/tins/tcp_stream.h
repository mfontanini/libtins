/*
 * Copyright (c) 2017, Matias Fontanini
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

#ifndef TINS_TCP_STREAM_H
#define TINS_TCP_STREAM_H

#include <map>
#include <utility>
#include <vector>
#include <algorithm>
#include <stdint.h>
#include <tins/macros.h>
#include <tins/tcp.h>
#include <tins/ip.h>
#include <tins/ip_address.h>
#include <tins/utils/pdu_utils.h>

#ifdef TINS_HAVE_PCAP

#include <tins/sniffer.h>

namespace Tins {
class Sniffer;
class RawPDU;

/**
 * \class TCPStream
 * \brief Represents a TCP stream.
 */
class TINS_API TCPStream {
public:
    /**
     * The stream information.
     */
    struct StreamInfo {
        IPv4Address client_addr, server_addr;
        uint16_t client_port, server_port;
        
        StreamInfo() : client_port(0), server_port(0) {}
        
        StreamInfo(IPv4Address client, IPv4Address server,
                   uint16_t cport, uint16_t sport);
        
        bool operator<(const StreamInfo& rhs) const;
    };
    
    /**
     * The type used to store the payload.
     */
    typedef std::vector<uint8_t> payload_type;

    /**
     * \brief TCPStream constructor.
     * \param ip The IP PDU from which to take the initial parameters.
     * \param tcp The TCP PDU from which to take the initial parameters.
     * \param identifier This stream's identifier number
     */
    TCPStream(IP* ip, TCP* tcp, uint64_t identifier);
    
    /**
     * Copy constructor.
     */
    TCPStream(const TCPStream& rhs);
    
    /**
     * Copy assignment operator.
     */
    TCPStream& operator=(const TCPStream& rhs);
    
    /**
     * Destructor.
     */
    ~TCPStream();
    
    /**
     * \brief Retrieves the client payload.
     * 
     * This is the payload that the connection's client has sent so far.
     * 
     * \return const payload_type& containing the payload.
     */
    const payload_type& client_payload() const {
        return client_payload_;
    }
    
    /**
     * \brief Retrieves the client payload.
     * 
     * This is the payload that the connection's client has sent so far.
     * 
     * \return payload_type& containing the payload.
     */
    payload_type& client_payload() {
        return client_payload_;
    }
    
    /**
     * \brief Retrieves the server payload.
     * 
     * This is the payload that the connection's server has sent so far.
     * 
     * \return const payload_type& containing the payload.
     */
    const payload_type& server_payload() const {
        return server_payload_;
    }
    
    /**
     * \brief Retrieves the server payload.
     * 
     * This is the payload that the connection's server has sent so far.
     * 
     * \return payload_type& containing the payload.
     */
    payload_type& server_payload() {
        return server_payload_;
    }

    /**
     * \brief Retrieves this stream's identification number.
     * \return uint64_t containing the identification number.
     */
    uint64_t id() const {
        return identifier_;
    }
    
    /**
     * \brief Retrieves the stream information.
     * \return const StreamInfo& containing the stream information.
     */
    const StreamInfo& stream_info() const {
        return info_;
    }

    /**
     * \brief Checks whether this stream is finished.
     * 
     * A stream is considered to be finished, if at least one of the 
     * peers sends a TCP segment containing the FIN bit on.
     * 
     * \return bool indicating whether the stream is finished.
     */
    bool is_finished() const {
        return fin_sent_;
    }
    
    /**
     * \brief Updates the stream data.
     * 
     * This may update both the payload and the expected sequence numbers.
     * 
     * \param ip The IP PDU from which to take information.
     * \param tcp The TCP PDU from which to take information.
     * \return bool indicating whether any changes have been done to 
     * any of the stored payloads.
     */
    bool update(IP* ip, TCP* tcp);
private:
    typedef std::map<uint32_t, RawPDU*> fragments_type;
    
    static void free_fragments(fragments_type& frags);
    static fragments_type clone_fragments(const fragments_type& frags);
    
    bool generic_process(uint32_t& my_seq, uint32_t& other_seq, 
      payload_type& pload, fragments_type& frags, TCP* tcp);

    void safe_insert(fragments_type& frags, uint32_t seq, RawPDU* raw);


    uint32_t client_seq_, server_seq_;
    StreamInfo info_;
    uint64_t identifier_;
    payload_type client_payload_, server_payload_;
    fragments_type client_frags_, server_frags_;
    bool syn_ack_sent_, fin_sent_;
};


/**
 * \class TCPStreamFollower
 * \brief Follows TCP streams and notifies the user when data is available.
 */
class TINS_API TCPStreamFollower {
public:
    /**
     * \brief Default constructor.
     */
    TCPStreamFollower();

    /**
     * \brief Starts following TCP streams.
     * 
     * The template functors must accept a TCPStream& as argument, which
     * will point to the stream which has been modified.
     * 
     * \param sniffer The sniffer which will be used to sniff PDUs.
     * \param data_fun The function which will be called whenever one of
     * the peers in a connection sends data.
     * \param end_fun This function will be called when a stream is 
     * closed.
     */
    template<typename DataFunctor, typename EndFunctor>
    void follow_streams(BaseSniffer& sniffer, DataFunctor data_fun, EndFunctor end_fun);
    
    /**
     * \brief Starts following TCP streams.
     * 
     * This overload takes a range of iterators containing the PDUs 
     * in which TCP streams will be looked up and followed. The iterators
     * will be dereferenced until a PDU& is found, so iterators can hold
     * not only PDUs, but also smart pointers, etc.
     * 
     * The template functors must accept a TCPStream& as argument, which
     * will point to the stream which has been modified.
     * 
     * The state of the PDUs stored in the iterator range provided might
     * be modified internally.
     * 
     * \param start The start of the range of PDUs.
     * \param end The start of the range of PDUs.
     * \param data_fun The function which will be called whenever one of
     * the peers in a connection sends data.
     * \param end_fun This function will be called when a stream is 
     * closed.
     */
    template<typename ForwardIterator, typename DataFunctor, typename EndFunctor>
    void follow_streams(ForwardIterator start, ForwardIterator end, 
      DataFunctor data_fun, EndFunctor end_fun);
    
    /**
     * \brief Starts following TCP streams.
     * 
     * The template functor must accept a TCPStream& as argument, which
     * will point to the stream which has been modified.
     * 
     * \param sniffer The sniffer which will be used to sniff PDUs.
     * \param data_fun The function which will be called whenever one of
     * the peers in a connection sends data.
     * closed.
     */
    template<typename DataFunctor>
    void follow_streams(BaseSniffer& sniffer, DataFunctor data_fun);
    
    /**
     * \brief Starts following TCP streams.
     * 
     * This overload takes a range of iterators containing the PDUs 
     * in which TCP streams will be looked up and followed. The iterators
     * will be dereferenced until a PDU& is found, so iterators can hold
     * not only PDUs, but also smart pointers, etc.
     * 
     * The template functors must accept a TCPStream& as argument, which
     * will point to the stream which has been modified.
     * 
     * The state of the PDUs stored in the iterator range provided might
     * be modified internally.
     * 
     * \param start The start of the range of PDUs.
     * \param end The start of the range of PDUs.
     * \param data_fun The function which will be called whenever one of
     * the peers in a connection sends data.
     */
    template<typename ForwardIterator, typename DataFunctor>
    void follow_streams(ForwardIterator start, ForwardIterator end, 
      DataFunctor data_fun);
private:
    typedef std::map<TCPStream::StreamInfo, TCPStream> sessions_type;
    
    template<typename DataFunctor, typename EndFunctor>
    struct proxy_caller {
        bool callback(PDU& pdu) {
            return stream->callback(pdu, data_fun, end_fun);
        }
        
        TCPStreamFollower* stream;
        DataFunctor data_fun;
        EndFunctor end_fun;
    };
    
    template<typename DataFunctor, typename EndFunctor>
    bool callback(PDU& pdu, const DataFunctor& fun, const EndFunctor& end_fun);
    static void dummy_function(TCPStream&) { }
    
    sessions_type sessions_;
    uint64_t last_identifier_;
};

template<typename DataFunctor, typename EndFunctor>
void TCPStreamFollower::follow_streams(BaseSniffer& sniffer, 
                                       DataFunctor data_fun,
                                       EndFunctor end_fun) {
    typedef proxy_caller<DataFunctor, EndFunctor> proxy_type;
    proxy_type proxy = { this, data_fun, end_fun };
    sniffer.sniff_loop(make_sniffer_handler(&proxy, &proxy_type::callback));
}

template<typename ForwardIterator, typename DataFunctor, typename EndFunctor>
void TCPStreamFollower::follow_streams(ForwardIterator start, 
                                       ForwardIterator end, 
                                       DataFunctor data_fun,
                                       EndFunctor end_fun)  {
    while(start != end) {
        if (!callback(Utils::dereference_until_pdu(start), data_fun, end_fun)) {
            return;
        }
        start++;
    }
}

template<typename DataFunctor>
void TCPStreamFollower::follow_streams(BaseSniffer& sniffer, DataFunctor data_fun) {
    return follow_streams(sniffer, data_fun, dummy_function);
}

template<typename ForwardIterator, typename DataFunctor>
void TCPStreamFollower::follow_streams(ForwardIterator start,
                                       ForwardIterator end, 
                                       DataFunctor data_fun) {
    follow_streams(start, end, data_fun, dummy_function);
}

template<typename DataFunctor, typename EndFunctor>
bool TCPStreamFollower::callback(PDU& pdu, 
                                 const DataFunctor& data_fun,
                                 const EndFunctor& end_fun) {
    IP* ip = pdu.find_pdu<IP>();
    TCP* tcp = pdu.find_pdu<TCP>();
    if (!ip || !tcp) {
        return true;
    }
    TCPStream::StreamInfo info( 
        ip->src_addr(), ip->dst_addr(),
        tcp->sport(), tcp->dport()
    );
    sessions_type::iterator it = sessions_.find(info);
    if (it == sessions_.end()) {
        std::swap(info.client_addr, info.server_addr);
        std::swap(info.client_port, info.server_port);
        if ((it = sessions_.find(info)) == sessions_.end()) {
            if (tcp->get_flag(TCP::SYN) && !tcp->get_flag(TCP::ACK)) {
                sessions_.insert(
                    std::make_pair(
                        info,
                        TCPStream(ip, tcp, last_identifier_++)
                    )
                );
            }
            return true;
        }
    }
    if (it->second.update(ip, tcp)) {
        data_fun(it->second);
    }
    // We're done with this stream
    if (it->second.is_finished()) {
        end_fun(it->second);
        sessions_.erase(it);
    }
    return true;
}

} // Tins

#endif // TINS_HAVE_PCAP

#endif // TINS_TCP_STREAM_H
