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

#ifndef TINS_TCP_STREAM_H
#define TINS_TCP_STREAM_H

#include <map>
#include <utility>
#include <vector>
#include <algorithm>
#include <stdint.h>
#include "sniffer.h"
#include "tcp.h"
#include "ip.h"
#include "ipaddress.h"

namespace Tins {
class Sniffer;
class RawPDU;

class TCPSession {
public:
    struct SessionInfo {
        IPv4Address client_addr, server_addr;
        uint16_t client_port, server_port;
        
        SessionInfo() {}
        
        SessionInfo(IPv4Address client, IPv4Address server,
            uint16_t cport, uint16_t sport);
        
        bool operator<(const SessionInfo &rhs) const;
    };

    typedef std::vector<uint8_t> payload_type;

    TCPSession(IP *ip, TCP *tcp, uint64_t identifier);
    TCPSession(const TCPSession &rhs);
    TCPSession& operator=(const TCPSession &rhs);
    ~TCPSession();
    
    const payload_type &client_payload() const {
        return client_payload_;
    }
    
    const payload_type &server_payload() const {
        return server_payload_;
    }
    
    uint64_t id() const {
        return identifier;
    }
    
    const SessionInfo &session_info() const {
        return info;
    }
    
    bool is_finished() const {
        return fin_sent;
    }
    
    bool update(IP *ip, TCP *tcp);
    void clear_client_payload();
    void clear_server_payload();

    bool operator<(const TCPSession &rhs) const;
private:
    typedef std::map<uint32_t, RawPDU*> fragments_type;
    
    static void free_fragments(fragments_type &frags);
    static fragments_type clone_fragments(const fragments_type &frags);
    
    bool generic_process(uint32_t &my_seq, uint32_t &other_seq, 
      payload_type &pload, fragments_type &frags, TCP *tcp, RawPDU *raw);

    uint32_t client_seq, server_seq;
    SessionInfo info;
    uint64_t identifier;
    payload_type client_payload_, server_payload_;
    fragments_type client_frags, server_frags;
    bool fin_sent;
};

class TCPStreamFollower {
public:
    TCPStreamFollower();

    template<typename DataFunctor, typename EndFunctor>
    void follow_streams(Sniffer &sniffer, DataFunctor data_fun, EndFunctor end_fun);
private:
    typedef std::map<TCPSession::SessionInfo, TCPSession> sessions_type;
    
    template<typename DataFunctor, typename EndFunctor>
    struct proxy_caller {
        bool callback(PDU *pdu) {
            return stream->callback(pdu, data_fun, end_fun);
        }
        
        TCPStreamFollower *stream;
        DataFunctor data_fun;
        EndFunctor end_fun;
    };
    
    template<typename DataFunctor, typename EndFunctor>
    bool callback(PDU *pdu, const DataFunctor &fun, const EndFunctor &end_fun);
    
    sessions_type sessions;
    uint64_t last_identifier;
};

template<typename DataFunctor, typename EndFunctor>
void TCPStreamFollower::follow_streams(Sniffer &sniffer, DataFunctor data_fun, EndFunctor end_fun) {
    typedef proxy_caller<DataFunctor, EndFunctor> proxy_type;
    proxy_type proxy = { this, data_fun, end_fun };
    sniffer.sniff_loop(make_sniffer_handler(&proxy, &proxy_type::callback));
}

template<typename DataFunctor, typename EndFunctor>
bool TCPStreamFollower::callback(PDU *pdu, const DataFunctor &data_fun, const EndFunctor &end_fun) {
    IP *ip = pdu->find_pdu<IP>();
    TCP *tcp = pdu->find_pdu<TCP>();
    if(ip && tcp) {
        TCPSession::SessionInfo info = { 
            ip->src_addr(), ip->dst_addr(),
            tcp->sport(), tcp->dport()
        };
        sessions_type::iterator it = sessions.find(info);
        if(it == sessions.end()) {
            std::swap(info.client_addr, info.server_addr);
            std::swap(info.client_port, info.server_port);
            if((it = sessions.find(info)) == sessions.end()) {
                if(tcp->get_flag(TCP::SYN) && !tcp->get_flag(TCP::ACK)) {
                    sessions.insert(
                        std::make_pair(
                            info,
                            TCPSession(ip, tcp, last_identifier++)
                        )
                    );
                }
                return true;
            }
        }
        if(it->second.update(ip, tcp))
            data_fun(it->second);
        // We're done with this stream
        if(it->second.is_finished()) {
            end_fun(it->second);
            sessions.erase(it);
        }
        return true;
    }
}
}

#endif // TINS_TCP_STREAM_H
