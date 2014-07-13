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

#include "handshake_capturer.h"

#ifdef HAVE_DOT11

#include "dot11/dot11_data.h"

namespace Tins {
    bool RSNHandshakeCapturer::process_packet(const PDU &pdu) {
        const RSNEAPOL *eapol = pdu.find_pdu<RSNEAPOL>();
        const Dot11Data *dot11 = pdu.find_pdu<Dot11Data>();
        if(!eapol || !dot11)
            return false;
        
        
        std::pair<address_type, address_type> addresses;
        if(dot11->to_ds()) {
            addresses.first = dot11->addr1();
            addresses.second = dot11->addr2();
        }
        else if(dot11->from_ds()) {
            addresses.first = dot11->addr2();
            addresses.second = dot11->addr1();
        }
        else
            return false;
            
        // 1st    
        if(eapol->key_t() && eapol->key_ack() && !eapol->key_mic() && !eapol->install()) {
            handshakes_[addresses].assign(eapol, eapol + 1);
        }
        else if(eapol->key_t() && eapol->key_mic() && !eapol->install() && !eapol->key_ack()) {
            if(*std::max_element(eapol->nonce(), eapol->nonce() + RSNEAPOL::nonce_size) > 0)
                do_insert(addresses, eapol, 1);
            else if(do_insert(addresses, eapol, 3)) {
                completed_handshakes_.push_back(
                    handshake_type(
                        addresses.first,
                        addresses.second,
                        handshakes_[addresses]
                    )
                );
                handshakes_.erase(addresses);
                return true;
            }
        }
        else if(eapol->key_t() && eapol->install() && eapol->key_ack() && eapol->key_mic()) {
            do_insert(addresses, eapol, 2);
        }
        return false;
    }
    
    bool RSNHandshakeCapturer::do_insert(const handshake_map::key_type &key, 
      const RSNEAPOL *eapol, size_t expected)
    {
        handshake_map::iterator iter = handshakes_.find(key);
        if(iter != handshakes_.end()) {
            if(iter->second.size() != expected) {
                // skip repeated
                if(iter->second.size() != expected + 1)
                    iter->second.clear();
            }
            else {
                iter->second.push_back(*eapol);
                return true;
            }
        }
        return false;
    }
} // namespace Tins;

#endif // HAVE_DOT11
