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
    class WEPDecrypter {
    public:
        typedef Dot11::address_type address_type;
    
        /**
         * \brief Constructs a WEPDecrypter object.
         */
        WEPDecrypter();
        
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
         * with the Dot11 packet's BSSID, then the PDU is left intact. 
         * 
         * Otherwise, the packet is decrypted using the given password. 
         * If the CRC found after decrypting it is invalid,
         * then false is returned.
         * 
         * \return false if decryption failed due to invalid CRC, true
         * otherwise.
         */
        bool decrypt(PDU &pdu);
    private:
        typedef std::map<address_type, std::string> passwords_type;
    
        PDU *decrypt(RawPDU &raw, const std::string &password);
    
        passwords_type passwords;
        std::vector<uint8_t> key_buffer;
    };

    /**
     * \brief Pluggable decrypter object which can be used to decrypt
     * data on sniffing sessions.
     * 
     * This class holds a decrypter object and a functor, and implements
     * a suitable operator() to be used on BaseSniffer::sniff_loop, which
     * decrypts packets and forwards them to the given functor.
     */
    template<typename Functor, typename Decrypter>
    class DecrypterProxy {
    public:
        /**
         * The type of the functor object.
         */
        typedef Functor functor_type;
    
        /**
         * The type of the decrypter object.
         */
        typedef Decrypter decrypter_type;
        
        /**
         * \brief Constructs an object from a functor and a decrypter.
         * \param func The functor to be used to forward decrypted 
         * packets.
         * \param decrypter The decrypter which will be used to decrypt
         * packets
         */
        DecrypterProxy(const functor_type &func, 
          const decrypter_type &decr = decrypter_type());
        
        /**
         * \brief Retrieves a reference to the decrypter object.
         */
        decrypter_type &decrypter();
        
        /**
         * \brief Retrieves a const reference to the decrypter object.
         */
        const decrypter_type &decrypter() const;
        
        /**
         * \brief The operator() which decrypts packets and forwards
         * them to the functor.
         */
        bool operator() (PDU &pdu);
    private:
        Functor functor_;
        decrypter_type decrypter_;
    };

    /**
     * \brief Performs RC4 encription/decryption of the given byte range,
     * using the provided key.
     * 
     * The decrypted range will be copied to the OutputIterator provided.
     * 
     * \param start The beginning of the range.
     * \param start The end of the range.
     * \param key The key to be used.
     * \param output The iterator in which to write the output.
     */
    template<typename ForwardIterator, typename OutputIterator>
    void rc4(ForwardIterator start, ForwardIterator end, RC4Key &key, OutputIterator output);
    
    /**
     * \brief Wrapper function to create DecrypterProxyes using a 
     * WEPDecrypter as the Decrypter template parameter.
     * 
     * \param functor The functor to be forwarded to the DecrypterProxy
     * constructor.
     */
    template<typename Functor>
    DecrypterProxy<Functor, WEPDecrypter> make_wep_decrypter_proxy(const Functor &functor);
    
    // Implementation section
    
    // DecrypterProxy
    
    template<typename Functor, typename Decrypter>
    DecrypterProxy<Functor, Decrypter>::DecrypterProxy(
      const functor_type &func, const decrypter_type& decr) 
    : functor_(func), decrypter_(decr)
    {
        
    }

    template<typename Functor, typename Decrypter>
    typename DecrypterProxy<Functor, Decrypter>::decrypter_type &
      DecrypterProxy<Functor, Decrypter>::decrypter() 
    {
        return decrypter_;
    }

    template<typename Functor, typename Decrypter>
    const typename DecrypterProxy<Functor, Decrypter>::decrypter_type &
      DecrypterProxy<Functor, Decrypter>::decrypter() const 
    {
        return decrypter_;
    }

    template<typename Functor, typename Decrypter>
    bool DecrypterProxy<Functor, Decrypter>::operator() (PDU &pdu) 
    {
        return decrypter_.decrypt(pdu) ? functor_(pdu) : true;
    }
    
    template<typename Functor>
    DecrypterProxy<Functor, WEPDecrypter> make_wep_decrypter_proxy(const Functor &functor)
    {
        return DecrypterProxy<Functor, WEPDecrypter>(functor);
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
