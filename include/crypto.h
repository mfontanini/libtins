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

#ifndef TINS_CRYPTO_H
#define TINS_CRYPTO_H

#include <map>
#include <string>
#include <algorithm>
#include <vector>
#include "dot11.h"
#include "utils.h"
#include "snap.h"
#include "rawpdu.h"

namespace Tins {
class PDU;

namespace Crypto {
    /**
     * \brief RC4 Key abstraction.
     */
    struct RC4Key {
        static const size_t data_size = 256;

        /**
         * \brief Initializes the key using the provided iterator range.
         * 
         * \param start The start of the range.
         * \param end The end of the range.
         */
        template<typename ForwardIterator>
        RC4Key(ForwardIterator start, ForwardIterator end);

        /**
         * The actual key data.
         */
        uint8_t data[data_size];
    };

    /**
     * 
     */
    template<typename Functor>
    class WEPDecrypter {
    public:
        typedef Dot11::address_type address_type;
    
        /**
         * \brief Constructs a WEPDecrypter from a Functor object.
         * 
         * \param func The functor which will be used to handle decrypted
         * packets.
         */
        WEPDecrypter(Functor func);
        
        /**
         * \brief Adds a decryption password.
         * 
         * \param addr The access point's BSSID.
         * \param password The password which will be used to decrypt
         * packets sent from and to the AP identifier by the BSSID addr.
         */
        void add_password(const address_type &addr, const std::string &password);
        
        /**
         * \brief Removes a decryption password
         * 
         * \param addr The BSSID of the access point.
         */
        void remove_password(const address_type &addr);
        
        /**
         * \brief Decrypts the provided PDU and forwards the decrypted
         * PDU to the functor held by this object.
         * 
         * A Dot11Data PDU is looked up inside the provided PDU chain.
         * If no such PDU exists or there is no password associated
         * with the Dot11 packet's BSSID, then the functor is called 
         * using the pdu parameter as its argument. 
         * 
         * Otherwise, the packet is decrypted using the given password
         * and the functor is called using the decrypted packet as its
         * argument. If the CRC found after decrypting it is invalid,
         * then the packet is discarded.
         * 
         */
        bool operator()(PDU &pdu);
    private:
        typedef std::map<address_type, std::string> passwords_type;
    
        PDU *decrypt(RawPDU &raw, const std::string &password);
    
        Functor functor;
        passwords_type passwords;
        std::vector<uint8_t> key_buffer;
    };

    template<typename ForwardIterator, typename OutputIterator>
    void rc4(ForwardIterator start, ForwardIterator end, RC4Key &key, OutputIterator output);
    
    
    // Implementation section
    
    // WEP Decrypter
    
    template<typename Functor>
    WEPDecrypter<Functor>::WEPDecrypter(Functor func) 
    : functor(func), key_buffer(4) {
        
    }
    
    template<typename Functor>
    void WEPDecrypter<Functor>::add_password(const address_type &addr, const std::string &password) {
        passwords[addr] = password;
        key_buffer.resize(std::max(3 + password.size(), key_buffer.size()));
    }
    
    template<typename Functor>
    void WEPDecrypter<Functor>::remove_password(const address_type &addr) {
        passwords.erase(addr);
    }
    
    template<typename Functor>
    bool WEPDecrypter<Functor>::operator() (PDU &pdu) {
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
                    // Invalid WEP packet(CRC check failed). Skip it.
                    if(!dot11->inner_pdu())
                        return true;
                }
            }
        }
        return functor(pdu);
    }
    
    template<typename Functor>
    PDU *WEPDecrypter<Functor>::decrypt(RawPDU &raw, const std::string &password) {
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
    
    // RC4 stuff
    
    template<typename ForwardIterator>
    RC4Key::RC4Key(ForwardIterator start, ForwardIterator end) {
        for(size_t i = 0; i < data_size; ++i)
            data[i] = i;
        size_t j = 0;
        ForwardIterator iter = start;
        for(size_t i = 0; i < data_size; ++i) {
            j = (j + data[i] + *iter++) % 256;
            if(iter == end)
                iter = start;
            std::swap(data[i], data[j]);
        }
    }
    
    template<typename ForwardIterator, typename OutputIterator>
    void rc4(ForwardIterator start, ForwardIterator end, RC4Key &key, OutputIterator output) {
        size_t i = 0, j = 0;
        while(start != end) {
            i = (i + 1) % RC4Key::data_size;
            j = (j + key.data[i]) % RC4Key::data_size;
            std::swap(key.data[i], key.data[j]);
            *output++ = *start++ ^ key.data[(key.data[i] + key.data[j]) % RC4Key::data_size];
        }
    }
}
}

#endif // TINS_CRYPTO_H
