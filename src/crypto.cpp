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

#include "crypto.h"

#ifdef HAVE_DOT11

#ifdef HAVE_WPA2_DECRYPTION
    #include <openssl/evp.h>
    #include <openssl/hmac.h>
    #include <openssl/aes.h>
#endif // HAVE_WPA2_DECRYPTION
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
                // If its valid, then return true
                if(dot11->inner_pdu()) {
                    // it's no longer encrypted.
                    dot11->wep(0);
                    return true;
                }
            }
        }
    }
    return false;
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

const uint16_t sbox_table[2][256]= {
    {
        0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
        0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
        0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
        0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
        0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
        0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
        0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
        0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
        0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
        0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
        0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
        0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
        0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
        0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
        0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
        0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
        0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
        0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
        0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
        0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
        0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
        0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
        0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
        0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
        0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
        0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
        0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
        0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
        0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
        0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
        0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
        0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A
    },
    {
        0xA5C6, 0x84F8, 0x99EE, 0x8DF6, 0x0DFF, 0xBDD6, 0xB1DE, 0x5491,
        0x5060, 0x0302, 0xA9CE, 0x7D56, 0x19E7, 0x62B5, 0xE64D, 0x9AEC,
        0x458F, 0x9D1F, 0x4089, 0x87FA, 0x15EF, 0xEBB2, 0xC98E, 0x0BFB,
        0xEC41, 0x67B3, 0xFD5F, 0xEA45, 0xBF23, 0xF753, 0x96E4, 0x5B9B,
        0xC275, 0x1CE1, 0xAE3D, 0x6A4C, 0x5A6C, 0x417E, 0x02F5, 0x4F83,
        0x5C68, 0xF451, 0x34D1, 0x08F9, 0x93E2, 0x73AB, 0x5362, 0x3F2A,
        0x0C08, 0x5295, 0x6546, 0x5E9D, 0x2830, 0xA137, 0x0F0A, 0xB52F,
        0x090E, 0x3624, 0x9B1B, 0x3DDF, 0x26CD, 0x694E, 0xCD7F, 0x9FEA,
        0x1B12, 0x9E1D, 0x7458, 0x2E34, 0x2D36, 0xB2DC, 0xEEB4, 0xFB5B,
        0xF6A4, 0x4D76, 0x61B7, 0xCE7D, 0x7B52, 0x3EDD, 0x715E, 0x9713,
        0xF5A6, 0x68B9, 0x0000, 0x2CC1, 0x6040, 0x1FE3, 0xC879, 0xEDB6,
        0xBED4, 0x468D, 0xD967, 0x4B72, 0xDE94, 0xD498, 0xE8B0, 0x4A85,
        0x6BBB, 0x2AC5, 0xE54F, 0x16ED, 0xC586, 0xD79A, 0x5566, 0x9411,
        0xCF8A, 0x10E9, 0x0604, 0x81FE, 0xF0A0, 0x4478, 0xBA25, 0xE34B,
        0xF3A2, 0xFE5D, 0xC080, 0x8A05, 0xAD3F, 0xBC21, 0x4870, 0x04F1,
        0xDF63, 0xC177, 0x75AF, 0x6342, 0x3020, 0x1AE5, 0x0EFD, 0x6DBF,
        0x4C81, 0x1418, 0x3526, 0x2FC3, 0xE1BE, 0xA235, 0xCC88, 0x392E,
        0x5793, 0xF255, 0x82FC, 0x477A, 0xACC8, 0xE7BA, 0x2B32, 0x95E6,
        0xA0C0, 0x9819, 0xD19E, 0x7FA3, 0x6644, 0x7E54, 0xAB3B, 0x830B,
        0xCA8C, 0x29C7, 0xD36B, 0x3C28, 0x79A7, 0xE2BC, 0x1D16, 0x76AD,
        0x3BDB, 0x5664, 0x4E74, 0x1E14, 0xDB92, 0x0A0C, 0x6C48, 0xE4B8,
        0x5D9F, 0x6EBD, 0xEF43, 0xA6C4, 0xA839, 0xA431, 0x37D3, 0x8BF2,
        0x32D5, 0x438B, 0x596E, 0xB7DA, 0x8C01, 0x64B1, 0xD29C, 0xE049,
        0xB4D8, 0xFAAC, 0x07F3, 0x25CF, 0xAFCA, 0x8EF4, 0xE947, 0x1810,
        0xD56F, 0x88F0, 0x6F4A, 0x725C, 0x2438, 0xF157, 0xC773, 0x5197,
        0x23CB, 0x7CA1, 0x9CE8, 0x213E, 0xDD96, 0xDC61, 0x860D, 0x850F,
        0x90E0, 0x427C, 0xC471, 0xAACC, 0xD890, 0x0506, 0x01F7, 0x121C,
        0xA3C2, 0x5F6A, 0xF9AE, 0xD069, 0x9117, 0x5899, 0x273A, 0xB927,
        0x38D9, 0x13EB, 0xB32B, 0x3322, 0xBBD2, 0x70A9, 0x8907, 0xA733,
        0xB62D, 0x223C, 0x9215, 0x20C9, 0x4987, 0xFFAA, 0x7850, 0x7AA5,
        0x8F03, 0xF859, 0x8009, 0x171A, 0xDA65, 0x31D7, 0xC684, 0xB8D0,
        0xC382, 0xB029, 0x775A, 0x111E, 0xCB7B, 0xFCA8, 0xD66D, 0x3A2C
    }
};

uint16_t sbox(uint16_t i) {
    return sbox_table[0][i & 0xff] ^ sbox_table[1][(i >> 8)];
}

uint16_t join_bytes(uint8_t b1, uint8_t b2) {
    return (static_cast<uint16_t>(b1) << 8) | b2;
}

uint16_t rotate(uint16_t value) {
    return ((value >> 1) & 0x7fff) | (value << 15);
}

uint16_t upper_byte(uint16_t value) {
    return (value >> 8) & 0xff;
}

uint16_t lower_byte(uint16_t value) {
    return value & 0xff;
}

HWAddress<6> get_bssid(const Dot11Data &dot11) {
    if(dot11.from_ds() && !dot11.to_ds())
        return dot11.addr3();
    else if(!dot11.from_ds() && dot11.to_ds())
        return dot11.addr2();
    else 
        return dot11.addr2();
}

namespace WPA2 {

SessionKeys::SessionKeys() {

}

SessionKeys::SessionKeys(const RSNHandshake &hs, const pmk_type &pmk) {
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
    is_ccmp = (hs.handshake()[3].key_descriptor() == 2);
}

SNAP *SessionKeys::ccmp_decrypt_unicast(const Dot11Data &dot11, RawPDU &raw) const {
    RawPDU::payload_type &pload = raw.payload();
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
        if(block_sz == 0)
            block_sz = 16;
        counter[14] = (i >> 8) & 0xff;
        counter[15] = i & 0xff;
        AES_encrypt(counter, crypted_block, &ctx );

        xor_range(crypted_block, &pload[offset], &pload[(i - 1) * 16], block_sz);
        
        xor_range(MIC, &pload[(i - 1) * 16], MIC, block_sz);
        AES_encrypt(MIC, MIC, &ctx);   
        offset += block_sz;
    }
    return (std::equal(nice_MIC, nice_MIC + sizeof(nice_MIC), MIC)) ? 
        new SNAP(&pload[0], total_sz) : 
        0;
}

RC4Key SessionKeys::generate_rc4_key(const Dot11Data &dot11, const RawPDU &raw) const {
    const RawPDU::payload_type &pload = raw.payload();
    const uint8_t *tk = ptk.begin() + 32;
    Internals::byte_array<16> rc4_key;
    uint16_t ppk[6];
    const Dot11::address_type addr = get_bssid(dot11);
    // Phase 1
    ppk[0] = join_bytes(pload[4], pload[5]);
    ppk[1] = join_bytes(pload[6], pload[7]);
    ppk[2] = join_bytes(addr[1], addr[0]);
    ppk[3] = join_bytes(addr[3], addr[2]);
    ppk[4] = join_bytes(addr[5], addr[4]);
    
    for(size_t i = 0; i < 4; ++i) {
        ppk[0] += sbox(ppk[4] ^ join_bytes(tk[1], tk[0]));
        ppk[1] += sbox(ppk[0] ^ join_bytes(tk[5], tk[4]));
        ppk[2] += sbox(ppk[1] ^ join_bytes(tk[9], tk[8]));
        ppk[3] += sbox(ppk[2] ^ join_bytes(tk[13], tk[12]));
        ppk[4] += sbox(ppk[3] ^ join_bytes(tk[1], tk[0])) + 2*i;
        ppk[0] += sbox(ppk[4] ^ join_bytes(tk[3], tk[2]));
        ppk[1] += sbox(ppk[0] ^ join_bytes(tk[7], tk[6]));
        ppk[2] += sbox(ppk[1] ^ join_bytes(tk[11], tk[10]));
        ppk[3] += sbox(ppk[2] ^ join_bytes(tk[15], tk[14]));
        ppk[4] += sbox(ppk[3] ^ join_bytes(tk[3], tk[2])) + 2*i + 1;
    }

    // Phase 2, step 1
    ppk[5] = ppk[4] + join_bytes(pload[0], pload[2]);
    
    // Phase 2, step 2
    ppk[0] += sbox(ppk[5] ^ join_bytes(tk[1], tk[0]));
    ppk[1] += sbox(ppk[0] ^ join_bytes(tk[3], tk[2]));
    ppk[2] += sbox(ppk[1] ^ join_bytes(tk[5], tk[4]));
    ppk[3] += sbox(ppk[2] ^ join_bytes(tk[7], tk[6]));
    ppk[4] += sbox(ppk[3] ^ join_bytes(tk[9], tk[8]));
    ppk[5] += sbox(ppk[4] ^ join_bytes(tk[11], tk[10]));
    
    ppk[0] += rotate(ppk[5] ^ join_bytes(tk[13], tk[12]));
    ppk[1] += rotate(ppk[0] ^ join_bytes(tk[15], tk[14]));
    ppk[2] += rotate(ppk[1]);
    ppk[3] += rotate(ppk[2]);
    ppk[4] += rotate(ppk[3]);
    ppk[5] += rotate(ppk[4]);
    
    // Phase 2, step 3
    rc4_key[0] = upper_byte(join_bytes(pload[0], pload[2]));
    rc4_key[1] = (rc4_key[0] | 0x20) & 0x7f;
    rc4_key[2] = lower_byte(join_bytes(pload[0], pload[2]));
    rc4_key[3] = lower_byte((ppk[5] ^ join_bytes(tk[1], tk[0])) >> 1);
    rc4_key[4] = lower_byte(ppk[0]);
    rc4_key[5] = upper_byte(ppk[0]);
    rc4_key[6] = lower_byte(ppk[1]);
    rc4_key[7] = upper_byte(ppk[1]);
    rc4_key[8] = lower_byte(ppk[2]);
    rc4_key[9] = upper_byte(ppk[2]);
    rc4_key[10] = lower_byte(ppk[3]);
    rc4_key[11] = upper_byte(ppk[3]);
    rc4_key[12] = lower_byte(ppk[4]);
    rc4_key[13] = upper_byte(ppk[4]);
    rc4_key[14] = lower_byte(ppk[5]);
    rc4_key[15] = upper_byte(ppk[5]);
    return RC4Key(rc4_key.begin(), rc4_key.end());
}

SNAP *SessionKeys::tkip_decrypt_unicast(const Dot11Data &dot11, RawPDU &raw) const {
    // at least 20 bytes for IV + crc + stuff
    if(raw.payload_size() <= 20)
        return 0;
    Crypto::RC4Key key = generate_rc4_key(dot11, raw);
    RawPDU::payload_type &pload = raw.payload();
    rc4(pload.begin() + 8, pload.end(), key, pload.begin());

    uint32_t crc = Utils::crc32(&pload[0], pload.size() - 12);
    if(pload[pload.size() - 12] != (crc & 0xff) ||
        pload[pload.size() - 11] != ((crc >> 8) & 0xff) ||
        pload[pload.size() - 10] != ((crc >> 16) & 0xff) ||
        pload[pload.size() - 9] != ((crc >> 24) & 0xff))
        return 0;

    return new SNAP(&pload[0], pload.size() - 20);
}

SNAP *SessionKeys::decrypt_unicast(const Dot11Data &dot11, RawPDU &raw) const {
    return is_ccmp ? 
        ccmp_decrypt_unicast(dot11, raw) :
        tkip_decrypt_unicast(dot11, raw);
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

void WPA2Decrypter::add_ap_data(const std::string &psk, const std::string &ssid) {
    pmks.insert(std::make_pair(ssid, WPA2::SupplicantData(psk, ssid)));
}

void WPA2Decrypter::add_ap_data(const std::string &psk, const std::string &ssid,
  const address_type &addr) 
{
    add_ap_data(psk, ssid);
    add_access_point(ssid, addr);
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
            WPA2::SessionKeys session(hs, it->second.pmk());
            keys[addr_p] = session;
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

#endif // HAVE_DOT11
