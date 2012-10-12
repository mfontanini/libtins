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
 
#include "crypto.h"

namespace Tins {
namespace Crypto {
WEPDecrypter::WEPDecrypter() 
: key_buffer(4) {
    
}

void WEPDecrypter::add_password(const address_type &addr, const std::string &password) {
    passwords[addr] = password;
    key_buffer.resize(std::max(3 + password.size(), key_buffer.size()));
}

void WEPDecrypter::remove_password(const address_type &addr) {
    passwords.erase(addr); 
}

bool WEPDecrypter::decrypt(PDU &pdu) {
    Dot11Data *dot11 = pdu.find_pdu<Dot11Data>();
    if(dot11) {
        RawPDU *raw = dot11->find_pdu<RawPDU>();
        if(raw) {
            address_type addr;
            if(!dot11->from_ds() && !dot11->to_ds())
                addr = dot11->addr3();
            else if(!dot11->from_ds() && dot11->to_ds())
                addr = dot11->addr1();
            else if(dot11->from_ds() && !dot11->to_ds())
                addr = dot11->addr2();
            else
                // ????
                addr = dot11->addr3();
            passwords_type::iterator it = passwords.find(addr);
            if(it != passwords.end()) {
                dot11->inner_pdu(decrypt(*raw, it->second));
                dot11->wep(0);
                // Invalid WEP packet(CRC check failed). Skip it.
                if(!dot11->inner_pdu())
                    return false;
            }
        }
    }
    return true;
}

PDU *WEPDecrypter::decrypt(RawPDU &raw, const std::string &password) {
    RawPDU::payload_type &pload = raw.payload();
    // We require at least the IV, the encrypted checksum and something to decrypt
    if(pload.size() <= 8)
        return 0;
    std::copy(pload.begin(), pload.begin() + 3, key_buffer.begin());
    std::copy(password.begin(), password.end(), key_buffer.begin() + 3);
    
    // Generate the key
    RC4Key key(key_buffer.begin(), key_buffer.begin() + password.size() + 3);
    rc4(pload.begin() + 4, pload.end(), key, pload.begin());
    uint32_t crc = Utils::crc32(&pload[0], pload.size() - 8);
    if(pload[pload.size() - 8] != (crc & 0xff) ||
        pload[pload.size() - 7] != ((crc >> 8) & 0xff) ||
        pload[pload.size() - 6] != ((crc >> 16) & 0xff) ||
        pload[pload.size() - 5] != ((crc >> 24) & 0xff))
        return 0;
    
    try {
        return new SNAP(&pload[0], pload.size() - 8);
    }
    catch(std::runtime_error&) {
        return 0;
    }
}
}
}
