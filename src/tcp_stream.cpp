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
: client_seq(tcp->seq()), info(ip->src_addr(), ip->dst_addr(), 
  tcp->sport(), tcp->dport()), identifier(identifier), fin_sent(false)
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
        new_frags.insert(std::make_pair(it->first, it->second->clone_pdu()));
    return new_frags;
}

bool TCPStream::generic_process(uint32_t &my_seq, uint32_t &other_seq, 
  payload_type &pload, fragments_type &frags, TCP *tcp, RawPDU *raw) 
{
    //std::cout << "Entre, my seq: " << std::hex << my_seq << std::endl;
    bool added_some(false);
    if(tcp->get_flag(TCP::SYN))
        other_seq++;
    if(tcp->get_flag(TCP::FIN) || tcp->get_flag(TCP::RST))
        fin_sent = true;
    if(raw) {
        frags[tcp->seq()] = static_cast<RawPDU*>(tcp->release_inner_pdu()); 
        fragments_type::iterator it = frags.begin();
        while(it != frags.end() && it->first == my_seq) {
            //std::cout << "Consumo: " << my_seq << std::endl;
            pload.insert(
                pload.end(),
                it->second->payload().begin(), 
                it->second->payload().end()
            );
            //std::cout << "This size: " << it->second->payload_size() << std::endl;
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
    if(tcp->get_flag(TCP::SYN) && tcp->get_flag(TCP::ACK)) {
        server_seq = tcp->seq() + 1;
    }
    if(ip->src_addr() == info.client_addr)
        return generic_process(client_seq, server_seq, client_payload_, client_frags, tcp, raw);
    else
        return generic_process(server_seq, client_seq, server_payload_, server_frags, tcp, raw);
}

void TCPStream::clear_client_payload() {
    client_payload_.clear();
}

void TCPStream::clear_server_payload() {
    server_payload_.clear();
}
}
