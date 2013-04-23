/*
 * Copyright (c) 2012, Matias Fontanini
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

#include "rawpdu.h"
#include "tcp_stream.h"

namespace Tins {

TCPStreamFollower::TCPStreamFollower() : last_identifier(0) {
    
}



TCPStream::StreamInfo::StreamInfo(IPv4Address client, 
  IPv4Address server, uint16_t cport, uint16_t sport) 
: client_addr(client), server_addr(server), client_port(cport), 
  server_port(sport)
{
    
}




TCPStream::TCPStream(IP *ip, TCP *tcp, uint64_t identifier) 
: client_seq(tcp->seq()), server_seq(0), info(ip->src_addr(), 
  ip->dst_addr(), tcp->sport(), tcp->dport()), identifier(identifier), 
  syn_ack_sent(false), fin_sent(false)
{
    
}

TCPStream::TCPStream(const TCPStream &rhs) {
    *this = rhs;
}

TCPStream& TCPStream::operator=(const TCPStream &rhs) {
    client_seq = rhs.client_seq;
    server_seq = rhs.server_seq;
    info = rhs.info;
    identifier = rhs.identifier;
    syn_ack_sent = rhs.syn_ack_sent;
    fin_sent = rhs.fin_sent;
    client_payload_ = rhs.client_payload_;
    server_payload_ = rhs.server_payload_;
    client_frags = clone_fragments(rhs.client_frags);
    server_frags = clone_fragments(rhs.server_frags);
    return *this;
}

TCPStream::~TCPStream() {
    free_fragments(client_frags);
    free_fragments(server_frags);
}

void TCPStream::free_fragments(fragments_type &frags) {
    for(fragments_type::iterator it = frags.begin(); it != frags.end(); ++it)
        delete it->second;
}

TCPStream::fragments_type TCPStream::clone_fragments(const fragments_type &frags) {
    fragments_type new_frags;
    for(fragments_type::const_iterator it = frags.begin(); it != frags.end(); ++it)
        new_frags.insert(std::make_pair(it->first, it->second->clone()));
    return new_frags;
}

bool TCPStream::generic_process(uint32_t &my_seq, uint32_t &other_seq, 
  payload_type &pload, fragments_type &frags, TCP *tcp, RawPDU *raw) 
{
    bool added_some(false);
    if(tcp->get_flag(TCP::FIN) || tcp->get_flag(TCP::RST))
        fin_sent = true;
    if(raw && tcp->seq() >= my_seq) {
        frags[tcp->seq()] = static_cast<RawPDU*>(tcp->release_inner_pdu()); 
        fragments_type::iterator it = frags.begin();
        while(it != frags.end() && it->first == my_seq) {
            pload.insert(
                pload.end(),
                it->second->payload().begin(), 
                it->second->payload().end()
            );
            my_seq += it->second->payload_size();
            delete it->second;
            frags.erase(it);
            it = frags.begin();
            added_some = true;
        }
    }
    return added_some;
}

bool TCPStream::update(IP *ip, TCP *tcp) {
    RawPDU *raw = tcp->find_pdu<RawPDU>();
    if(!syn_ack_sent && tcp->get_flag(TCP::SYN) && tcp->get_flag(TCP::ACK)) {
        server_seq = tcp->seq() + 1;
        client_seq = tcp->ack_seq();
        syn_ack_sent = true;
        return false;
    }
    else {
        if(ip->src_addr() == info.client_addr)
            return generic_process(client_seq, server_seq, client_payload_, client_frags, tcp, raw);
        else
            return generic_process(server_seq, client_seq, server_payload_, server_frags, tcp, raw);
    }
}

bool TCPStream::StreamInfo::operator<(const StreamInfo &rhs) const {
    if(client_addr == rhs.client_addr) {
        if(server_addr == rhs.server_addr) {
            if(client_port == rhs.client_port) {
                return server_port < rhs.server_port;
            }
            else
                return client_port < rhs.client_port;
        }
        else
            return server_addr < rhs.server_addr;
    }
    else
        return client_addr < rhs.client_addr;
}
}
