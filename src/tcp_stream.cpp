/*
 * Copyright (c) 2016, Matias Fontanini
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

#include <limits>
#include "rawpdu.h"
#include "tcp_stream.h"

using std::numeric_limits;
using std::make_pair;

namespace Tins {

// As defined by RFC 1982 - 2 ^ (SERIAL_BITS - 1)
static const uint32_t seq_number_diff = 2147483648U;

// Adds sequence numbers
uint32_t add_sequence_numbers(uint32_t seq1, uint32_t seq2) {
    return seq1 + seq2;
}

// Subtract sequence numbers
uint32_t subtract_sequence_numbers(uint32_t seq1, uint32_t seq2) {
    return seq1 - seq2;
}

// Compares sequence numbers as defined by RFC 1982.
int compare_seq_numbers(uint32_t seq1, uint32_t seq2) {
    if (seq1 == seq2) {
        return 0;
    }
    if (seq1 < seq2) {
        return (seq2 - seq1 < seq_number_diff) ? -1 : 1;
    }
    else {
        return (seq1 - seq2 > seq_number_diff) ? -1 : 1;
    }
}

template<typename Iterator, typename Container>
Iterator erase_iterator(Iterator it, Container& cont) {
    Iterator output = it;
    ++output;
    cont.erase(it);
    if (output == cont.end()) {
        output = cont.begin();
    }
    return output;
}


// TCPStreamFollower

TCPStreamFollower::TCPStreamFollower()
: last_identifier_(0) {
    
}



TCPStream::StreamInfo::StreamInfo(IPv4Address client, 
                                  IPv4Address server,
                                  uint16_t cport,
                                  uint16_t sport) 
: client_addr(client), server_addr(server), client_port(cport), 
  server_port(sport) {
}




TCPStream::TCPStream(IP* ip, TCP* tcp, uint64_t identifier) 
: client_seq_(tcp->seq()), server_seq_(0), info_(ip->src_addr(), 
  ip->dst_addr(), tcp->sport(), tcp->dport()), identifier_(identifier), 
  syn_ack_sent_(false), fin_sent_(false) {
}

TCPStream::TCPStream(const TCPStream& rhs) {
    *this = rhs;
}

TCPStream& TCPStream::operator=(const TCPStream& rhs) {
    client_seq_ = rhs.client_seq_;
    server_seq_ = rhs.server_seq_;
    info_ = rhs.info_;
    identifier_ = rhs.identifier_;
    syn_ack_sent_ = rhs.syn_ack_sent_;
    fin_sent_ = rhs.fin_sent_;
    client_payload_ = rhs.client_payload_;
    server_payload_ = rhs.server_payload_;
    client_frags_ = clone_fragments(rhs.client_frags_);
    server_frags_ = clone_fragments(rhs.server_frags_);
    return* this;
}

TCPStream::~TCPStream() {
    free_fragments(client_frags_);
    free_fragments(server_frags_);
}

void TCPStream::free_fragments(fragments_type& frags) {
    for (fragments_type::iterator it = frags.begin(); it != frags.end(); ++it) {
        delete it->second;
    }
}

TCPStream::fragments_type TCPStream::clone_fragments(const fragments_type& frags) {
    fragments_type new_frags;
    for (fragments_type::const_iterator it = frags.begin(); it != frags.end(); ++it) {
        new_frags.insert(make_pair(it->first, it->second->clone()));
    }
    return new_frags;
}

void TCPStream::safe_insert(fragments_type& frags, uint32_t seq, RawPDU* raw) {
    RawPDU*& stored_raw = frags[seq];
    // New segment, insert it
    if (stored_raw == 0) {
        stored_raw = raw;
    }
    else {
        // There was a segment in this position. Keep the largest one.
        if (stored_raw->payload_size() > raw->payload_size()) {
            delete raw;
        }
        else {
            delete stored_raw;
            stored_raw = raw;
        }
    }
}

bool TCPStream::generic_process(uint32_t& my_seq,
                                uint32_t& /*other_seq*/,
                                payload_type& pload,
                                fragments_type& frags,
                                TCP* tcp) {
    bool added_some(false);
    if (tcp->get_flag(TCP::FIN) || tcp->get_flag(TCP::RST)) {
        fin_sent_ = true;
    }
    RawPDU* raw = static_cast<RawPDU*>(tcp->release_inner_pdu()); 
    if (raw) {
        const uint32_t chunk_end = add_sequence_numbers(tcp->seq(), raw->payload_size());
        // If the end of the chunk ends after our current sequence number, process it.
        if (compare_seq_numbers(chunk_end, my_seq) >= 0) {
            uint32_t seq = tcp->seq();
            // If it starts before our sequence number, slice it
            if (compare_seq_numbers(seq, my_seq) < 0) {
                const uint32_t diff = subtract_sequence_numbers(my_seq, seq);
                raw->payload().erase(
                    raw->payload().begin(),
                    raw->payload().begin() + diff
                );
                seq = my_seq;
            }
            safe_insert(frags, seq, raw);
            fragments_type::iterator it = frags.find(my_seq);
            // Keep looping while the fragments seq is lower or equal to our seq
            while (it != frags.end() && compare_seq_numbers(it->first, my_seq) <= 0) {
                // Does this fragment start before our sequence number?
                if (compare_seq_numbers(it->first, my_seq) < 0) {
                    uint32_t fragment_end = add_sequence_numbers(it->first, it->second->payload_size());
                    int comparison = compare_seq_numbers(fragment_end, my_seq);
                    // Does it end after our sequence number? 
                    if (comparison > 0) {
                        // Then slice it
                        RawPDU::payload_type& payload = it->second->payload();
                        payload.erase(
                            payload.begin(),
                            payload.begin() + subtract_sequence_numbers(my_seq, it->first)
                        );
                        safe_insert(frags, my_seq, it->second);
                        it = erase_iterator(it, frags);
                    }
                    else {
                        // Otherwise, we've seen this part of the payload. Erase it.
                        delete it->second;
                        it = erase_iterator(it, frags);
                    }
                }
                else {
                    // They're equal. Add this payload.
                    pload.insert(
                        pload.end(),
                        it->second->payload().begin(), 
                        it->second->payload().end()
                    );
                    my_seq += it->second->payload_size();
                    delete it->second;
                    it = erase_iterator(it, frags);
                    added_some = true;
                    if (frags.empty()) {
                        break;
                    }
                }
            }
        }
        else {
            delete raw;
        }
    }
    return added_some;
}

bool TCPStream::update(IP* ip, TCP* tcp) {
    if (!syn_ack_sent_) {
        if (tcp->flags() == (TCP::SYN | TCP::ACK)) {
            server_seq_ = tcp->seq() + 1;
            client_seq_ = tcp->ack_seq();
            syn_ack_sent_ = true;
        }
        return false;
    }
    else {
        if (ip->src_addr() == info_.client_addr && tcp->sport() == info_.client_port) {
            return generic_process(client_seq_, server_seq_, client_payload_, client_frags_, tcp);
        }
        else {
            return generic_process(server_seq_, client_seq_, server_payload_, server_frags_, tcp);
        }
    }
}

bool TCPStream::StreamInfo::operator<(const StreamInfo& rhs) const {
    if (client_addr == rhs.client_addr) {
        if (server_addr == rhs.server_addr) {
            if (client_port == rhs.client_port) {
                return server_port < rhs.server_port;
            }
            else {
                return client_port < rhs.client_port;
            }
        }
        else {
            return server_addr < rhs.server_addr;
        }
    }
    else {
        return client_addr < rhs.client_addr;
    }
}

} // Tins
