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

#include <iostream>  // borrame
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include "crypto.h"
#include "dot11/dot11_data.h"
#include "dot11/dot11_beacon.h"

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

#ifdef HAVE_WPA2_DECRYPTION
// WPA2Decrypter

const HWAddress<6> &min(const HWAddress<6>& lhs, const HWAddress<6>& rhs) {
    return lhs < rhs ? lhs : rhs;
}

const HWAddress<6> &max(const HWAddress<6>& lhs, const HWAddress<6>& rhs) {
    return lhs < rhs ? rhs : lhs;
}

template<typename InputIterator1, typename InputIterator2, typename OutputIterator>
void xor_range(InputIterator1 src1, InputIterator2 src2, OutputIterator dst, size_t sz) {
    for(size_t i = 0; i < sz; ++i) {
        *dst++ = *src1++ ^ *src2++;
    }
}

namespace WPA2 {
CCMPSessionKeys::CCMPSessionKeys(const RSNHandshake &hs, const pmk_type &pmk) {
    uint8_t PKE[100] = "Pairwise key expansion";
    uint8_t MIC[16];
    min(hs.client_address(), hs.supplicant_address()).copy(PKE + 23);
    max(hs.client_address(), hs.supplicant_address()).copy(PKE + 29);
    const uint8_t *nonce1 = hs.handshake()[1].nonce(), 
                  *nonce2 = hs.handshake()[2].nonce();
    if(std::lexicographical_compare(nonce1, nonce1 + 32, nonce2, nonce2 + 32)) {
        std::copy(nonce1, nonce1 + 32, PKE + 35);
        std::copy(nonce2, nonce2 + 32, PKE + 67);
    }
    else {
        std::copy(nonce2, nonce2 + 32, PKE + 35);
        std::copy(nonce1, nonce1 + 32, PKE + 67);
    }
    for(int i(0); i < 4; ++i) {
        PKE[99] = i;
        HMAC(EVP_sha1(), pmk.begin(), pmk.size(), PKE, 100, ptk.begin() + i * 20, 0);
    }
    PDU::serialization_type buffer = const_cast<RSNEAPOL&>(hs.handshake()[3]).serialize();
    std::fill(buffer.begin() + 81, buffer.begin() + 81 + 16, 0);
    if(hs.handshake()[3].key_descriptor() == 2)
        HMAC(EVP_sha1(), ptk.begin(), 16, &buffer[0], buffer.size(), MIC, 0);
    else
        HMAC(EVP_md5(), ptk.begin(), 16, &buffer[0], buffer.size(), MIC, 0);
    
    if(!std::equal(MIC, MIC + sizeof(MIC), hs.handshake()[3].mic()))
        throw invalid_handshake();
}

SNAP *CCMPSessionKeys::decrypt_unicast(const Dot11Data &dot11, const RawPDU &raw) const {
    const RawPDU::payload_type &pload = raw.payload();
    uint8_t MIC[16] = {0};
    uint8_t PN[6] = {
        pload[7],
        pload[6],
        pload[5],
        pload[4],
        pload[1],
        pload[0]
    };
    
    uint8_t AAD[32] = {0};
    AAD[0] = 0;
    AAD[1] = 22 + 6 * int(dot11.from_ds() && dot11.to_ds());
    if(dot11.subtype() == Dot11::QOS_DATA_DATA) 
        AAD[1] += 2;
    AAD[2] = dot11.protocol() | (dot11.type() << 2) | ((dot11.subtype() << 4) & 0x80);
    AAD[3] = 0x40 | dot11.to_ds() | (dot11.from_ds() << 1) |
            (dot11.more_frag() << 2) | (dot11.order() << 7);
    dot11.addr1().copy(AAD + 4);
    dot11.addr2().copy(AAD + 10);
    dot11.addr3().copy(AAD + 16);
    
    AAD[22] = dot11.frag_num();
    AAD[23] = 0;
    
    if(dot11.from_ds() && dot11.to_ds())
        dot11.addr4().copy(AAD + 24);
    
    AES_KEY ctx;
    AES_set_encrypt_key(ptk.begin() + 32, 128, &ctx);
    uint8_t crypted_block[16];
    size_t total_sz = raw.payload_size() - 16, offset = 8, blocks = (total_sz + 15) / 16;
    std::vector<uint8_t> output(total_sz);
    
    uint8_t counter[16];
    counter[0] = 0x59;
    counter[1] = 0;
    dot11.addr2().copy(counter + 2);
    std::copy(PN, PN + 6, counter + 8);
    counter[14] = (total_sz >> 8) & 0xff;
    counter[15] = total_sz & 0xff;
    
    AES_encrypt(counter, MIC, &ctx);
    xor_range(MIC, AAD, MIC, 16);
    AES_encrypt(MIC, MIC, &ctx);
    xor_range(MIC, AAD + 16, MIC, 16);
    AES_encrypt(MIC, MIC, &ctx);
    
    counter[0] = 1;
    counter[14] = counter[15] = 0;
    AES_encrypt(counter, crypted_block, &ctx);
    uint8_t nice_MIC[8];
    std::copy(pload.begin() + pload.size() - 8, pload.end(), nice_MIC);
    xor_range(crypted_block, nice_MIC, nice_MIC, 8);
    for(size_t i = 1; i <= blocks; ++i) {
        size_t block_sz = (i == blocks) ? (total_sz % 16) : 16;
        counter[14] = (i >> 8) & 0xff;
        counter[15] = i & 0xff;
        AES_encrypt(counter, crypted_block, &ctx );
        xor_range(crypted_block, &pload[offset], &output[(i - 1) * 16], block_sz);
        
        xor_range(MIC, &output[(i - 1) * 16], MIC, block_sz);
        AES_encrypt(MIC, MIC, &ctx);   
        offset += block_sz;
    }
    return (std::equal(nice_MIC, nice_MIC + sizeof(nice_MIC), MIC)) ? 
        new SNAP(&output[0], output.size()) : 
        0;
}

// supplicant_data

SupplicantData::SupplicantData(const std::string &psk, const std::string &ssid) {
    PKCS5_PBKDF2_HMAC_SHA1(
        psk.c_str(), 
        psk.size(), 
        (unsigned char *)ssid.c_str(), 
        ssid.size(), 
        4096, 
        pmk_.size(), 
        pmk_.begin()
    );
}

const SupplicantData::pmk_type &SupplicantData::pmk() const {
    return pmk_;
}
} // namespace WPA2

void WPA2Decrypter::add_supplicant_data(const std::string &psk, const std::string &ssid) {
    pmks.insert(std::make_pair(ssid, WPA2::SupplicantData(psk, ssid)));
}

void WPA2Decrypter::add_supplicant_data(const std::string &psk, const std::string &ssid,
  const address_type &addr) 
{
    // ADD CODE PLX
    add_supplicant_data(psk, ssid);
}

void WPA2Decrypter::add_access_point(const std::string &ssid, const address_type &addr) {
    pmks_map::const_iterator it = pmks.find(ssid);
    if(it == pmks.end()) 
        throw std::runtime_error("supplicant data not registered");
    aps.insert(std::make_pair(addr, it->second));
}

void WPA2Decrypter::try_add_keys(const Dot11Data &dot11, const RSNHandshake &hs) {
    bssids_map::const_iterator it = find_ap(dot11);
    if(it != aps.end()) {
        addr_pair addr_p = extract_addr_pair(dot11);
        try {
            keys.insert(std::make_pair(addr_p, WPA2::CCMPSessionKeys(hs, it->second.pmk())));
        }
        catch(WPA2::invalid_handshake&) { }
    }
}

WPA2Decrypter::addr_pair WPA2Decrypter::extract_addr_pair(const Dot11Data &dot11) {
    if(dot11.from_ds() && !dot11.to_ds())
        return make_addr_pair(dot11.addr2(), dot11.addr3());
    else if(!dot11.from_ds() && dot11.to_ds())
        return make_addr_pair(dot11.addr1(), dot11.addr2());
    else 
        return make_addr_pair(dot11.addr2(), dot11.addr3());
}

WPA2Decrypter::addr_pair WPA2Decrypter::extract_addr_pair_dst(const Dot11Data &dot11) {
    if(dot11.from_ds() && !dot11.to_ds())
        return make_addr_pair(dot11.addr1(), dot11.addr2());
    else if(!dot11.from_ds() && dot11.to_ds())
        return make_addr_pair(dot11.addr1(), dot11.addr3());
    else 
        return make_addr_pair(dot11.addr1(), dot11.addr3());
}

WPA2Decrypter::bssids_map::const_iterator WPA2Decrypter::find_ap(const Dot11Data &dot11) {
    if(dot11.from_ds() && !dot11.to_ds())
        return aps.find(dot11.addr2());
    else if(!dot11.from_ds() && dot11.to_ds())
        return aps.find(dot11.addr1());
    else 
        return aps.find(dot11.addr3());
}

bool WPA2Decrypter::decrypt(PDU &pdu) {
    if(capturer.process_packet(pdu)) {
        try_add_keys(pdu.rfind_pdu<Dot11Data>(), capturer.handshakes().front());
        capturer.clear_handshakes();
    }
    else if(const Dot11Beacon *beacon = pdu.find_pdu<Dot11Beacon>()) {
        if(aps.count(beacon->addr3()) == 0) {
            try {
                std::string ssid = beacon->ssid();
                if(pmks.count(ssid)) {
                    add_access_point(ssid, beacon->addr3());
                }
            }
            catch(option_not_found&) { }
        }
    }
    else {
        Dot11Data *data = pdu.find_pdu<Dot11Data>();
        RawPDU *raw = pdu.find_pdu<RawPDU>();
        if(data && raw && data->wep()) {
            // search for the tuple (bssid, src_addr)
            keys_map::const_iterator it = keys.find(extract_addr_pair(*data));
            
            // search for the tuple (bssid, dst_addr) if the above didn't work
            if(it == keys.end())
                it = keys.find(extract_addr_pair_dst(*data));
            if(it != keys.end()) {
                SNAP *snap = it->second.decrypt_unicast(*data, *raw);
                if(snap) {
                    data->inner_pdu(snap);
                    data->wep(0);
                    return true;
                }
            }
        }
    }
    return false;
} // namespace WPA2
#endif // HAVE_WPA2_DECRYPTION
} // namespace Crypto
} // namespace Tins
