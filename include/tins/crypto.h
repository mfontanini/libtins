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

#include "config.h"

#if !defined(TINS_CRYPTO_H) && defined(TINS_HAVE_DOT11)
#define TINS_CRYPTO_H

#include <map>
#include <string>
#include <algorithm>
#include <vector>
#ifdef TINS_HAVE_WPA2_CALLBACKS
    #include <functional>
#endif // TINS_HAVE_WPA2_CALLBACKS
#include "utils.h"
#include "snap.h"
#include "rawpdu.h"
#include "macros.h"
#include "handshake_capturer.h"

namespace Tins {

class PDU;
class Dot11;
class Dot11Data;

namespace Crypto {

struct RC4Key;

#ifdef TINS_HAVE_WPA2_DECRYPTION
namespace WPA2 {

/**
 * \brief Class that represents the keys used to decrypt a session.
 */
class TINS_API SessionKeys {
public:
    /**
     * The size of the Pairwise Master Key.
     */
    static const size_t PMK_SIZE;

    /**
     * The size of the Pairwise Transient Key.
     */
    static const size_t PTK_SIZE;

    /**
     * The type used to hold the PTK (this has to be PTK_SIZE bytes long).
     */
    typedef std::vector<uint8_t> ptk_type;

    /**
     * The type used to hold the PMK (this has to be PMK_SIZE bytes long).
     */
    typedef std::vector<uint8_t> pmk_type;
    
    /**
     * Default constructs a SessionKeys object.
     */
    SessionKeys();

    /**
     * \brief Constructs an instance using the provided PTK and a flag 
     * indicating whether it should use ccmp.
     *
     * \param ptk The PTK to use.
     * \param is_ccmp Indicates whether to use CCMP to decrypt this traffic.
     */
    SessionKeys(const ptk_type& ptk, bool is_ccmp);

    /**
     * \brief Constructs an instance using a handshake and a PMK.
     *
     * This will internally construct the PTK from the input parameters.
     *
     * \param hs The handshake to use.
     * \param pmk The PMK to use.
     */
    SessionKeys(const RSNHandshake& hs, const pmk_type& pmk);

    /**
     * \brief Decrypts a unicast packet.
     *
     * \param dot11 The encrypted packet to decrypt.
     * \param raw The raw layer on the packet to decrypt.
     * \return A SNAP layer containing the decrypted traffic or a null pointer
     * if decryption failed.
     */
    SNAP* decrypt_unicast(const Dot11Data& dot11, RawPDU& raw) const;

    /**
     * \brief Gets the PTK for this session keys.
     * \return The Pairwise Transcient Key.
     */
    const ptk_type& get_ptk() const;

    /**
     * \brief Indicates whether CCMP is used to decrypt packets
     * /return true iff CCMP is used.
     */
    bool uses_ccmp() const;
private:
    SNAP* ccmp_decrypt_unicast(const Dot11Data& dot11, RawPDU& raw) const;
    SNAP* tkip_decrypt_unicast(const Dot11Data& dot11, RawPDU& raw) const;
    RC4Key generate_rc4_key(const Dot11Data& dot11, const RawPDU& raw) const;

    ptk_type ptk_;
    bool is_ccmp_;
};

/**
 * \brief Represents a WPA2 supplicant's data.
 *
 * Objects of this class can be given the pre-shared key and the SSID
 * of some access point, and this will generate the Pairwise Master Key
 * from those parameters.
 */
class TINS_API SupplicantData {
public:
    /**
     * The type used to store the PMK.
     */
    typedef SessionKeys::pmk_type pmk_type;
    
    /**
     * \brief Constructs a SupplicantData.
     * \param psk The pre-shared key.
     * \param ssid The access point's SSID.
     */
    SupplicantData(const std::string& psk, const std::string& ssid);
    
    /**
     * \brief Getter for the PMK.
     * \return The generated PMK.
     */
    const pmk_type& pmk() const;

    /**
     * \brief Getter for the SSID
     * \return The access point's SSID
     */
    const std::string& ssid() const;
private:
    pmk_type pmk_;
    std::string ssid_;
};

} // WPA2
#endif // TINS_HAVE_WPA2_DECRYPTION

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
 * \brief Decrypts WEP-encrypted traffic.
 */
class TINS_API WEPDecrypter {
public:
    typedef HWAddress<6> address_type;

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
    void add_password(const address_type& addr, const std::string& password);
    
    /**
     * \brief Removes a decryption password
     * 
     * \param addr The BSSID of the access point.
     */
    void remove_password(const address_type& addr);
    
    /**
     * \brief Decrypts the provided PDU.
     * 
     * A Dot11Data PDU is looked up inside the provided PDU chain.
     * If no such PDU exists or there is no password associated
     * with the Dot11 packet's BSSID, then the PDU is left intact. 
     * 
     * Otherwise, the packet is decrypted using the given password. 
     * If the CRC found after decrypting is invalid, false is 
     * returned.
     * 
     * \return false if no decryption was performed or decryption 
     * failed, true otherwise.
     */
    bool decrypt(PDU& pdu);
private:
    typedef std::map<address_type, std::string> passwords_type;

    PDU* decrypt(RawPDU& raw, const std::string& password);

    passwords_type passwords_;
    std::vector<uint8_t> key_buffer_;
};

#ifdef TINS_HAVE_WPA2_DECRYPTION
/**
 * \brief Decrypts WPA2-encrypted traffic.
 *
 * This class takes valid PSK and SSID tuples, captures client handshakes,
 * and decrypts their traffic afterwards.
 */
class TINS_API WPA2Decrypter {
public:
    /*
     * \brief The type used to store Dot11 addresses.
     */
    typedef HWAddress<6> address_type;
    
    /**
     * \brief Represents a pair of mac addresses.
     * 
     * This is used to identify a host and the access point to which 
     * it is connected. The first element in the pair will always de
     * lower or equal than the second one, so that given any host and
     * the access point it's connected to, we can uniquely identify
     * it with an address pair.
     */
    typedef std::pair<address_type, address_type> addr_pair;

    /**
     * \brief Maps an address pair to the session keys.
     *
     * This type associates an address pair (host, access point) with the
     * session keys, as generated using the packets seen on a handshake.
     *
     * \sa addr_pair
     */
    typedef std::map<addr_pair, WPA2::SessionKeys> keys_map;

    #ifdef TINS_HAVE_WPA2_CALLBACKS

    /**
     * \brief The type used to store the callback type used when a new access
     * point is found.
     *
     * The first argument to the function will be the access point's SSID and
     * the second one its BSSID. 
     */
    typedef std::function<void(const std::string&,
                               const address_type&)> ap_found_callback_type;

    /**
     * The type used to store the callback type used when a new handshake
     * is captured.
     *
     * The first argument to the function will be the access point's SSID and
     * the second one its BSSID. The third argument will be the client's hardware
     * address.
     */
    typedef std::function<void(const std::string&,
                               const address_type&,
                               const address_type&)> handshake_captured_callback_type;
    
    #endif // TINS_HAVE_WPA2_CALLBACKS

    /**
     * \brief Adds an access points's information.
     *
     * This associates an SSID with a PSK, and allows the decryption of
     * any BSSIDs that broadcast the same SSID. 
     * 
     * The decrypter will inspect beacon frames, looking for SSID tags 
     * that contain the given SSID.
     *
     * Note that using this overload, the decryption of data frames and
     * handshake capturing will be disabled until any access point 
     * broadcasts the provided SSID(this shouldn't take long at all). 
     * If this is not the desired behaviour, then you should check out
     * the ovther add_ap_data overload.
     * 
     * \param psk The PSK associated with the SSID.
     * \param ssid The network's SSID.
     */
    void add_ap_data(const std::string& psk, const std::string& ssid);

    /**
     * \brief Adds a access points's information, including its BSSID.
     *
     * This overload can be used if the BSSID associated with this SSID is 
     * known beforehand. The addr parameter indicates which specific BSSID 
     * is associated to the SSID. 
     * 
     * Note that if any other access point broadcasts the provided SSID, 
     * it will be taken into account as well.
     * 
     * \param psk The PSK associated with this SSID.
     * \param ssid The network's SSID.
     * \param addr The access point's BSSID.
     */
    void add_ap_data(const std::string& psk,
                     const std::string& ssid,
                     const address_type& addr);
    
    /**
     * \brief Explicitly add decryption keys.
     * 
     * This method associates a pair (host, access point) with the given decryption keys.
     * All encrypted packets sent between the given addresses will be decrypted using the
     * provided keys.
     * 
     * This method shouldn't normally be required. The WPA2Decrypter will be waiting for
     * handshakes and will automatically extract the session keys, decrypting all 
     * encrypted packets with them. You should only use this method if for some reason
     * you know the actual keys being used (because you checked and stored the keys_map 
     * somewhere).
     *
     * The actual order of the addresses doesn't matter, this method will make sure
     * they're sorted.
     *
     * \param addresses The address pair (host, access point) to associate.
     * \param session_keys The keys to use when decrypting messages sent between the 
     * given addresses.
     */
    void add_decryption_keys(const addr_pair& addresses, 
                             const WPA2::SessionKeys& session_keys);

    /**
     * \brief Decrypts the provided PDU.
     * 
     * A Dot11Data PDU is looked up inside the provided PDU chain.
     * If no such PDU exists or no PSK was associated with the SSID
     * broadcasted by the Dot11 packet's BSSID, or no EAPOL handshake 
     * was captured for the client involved in the communication, 
     * then the PDU is left intact. 
     * 
     * Otherwise, the packet is decrypted using the generated PTK. 
     * If the resulting MIC is invalid, then the packet is left intact.
     * 
     * \return false if no decryption was performed, or the decryption 
     * failed, true otherwise.
     */
    bool decrypt(PDU& pdu);

    #ifdef TINS_HAVE_WPA2_CALLBACKS
    /**
     * \brief Sets the handshake captured callback
     * 
     * This callback will be executed every time a new handshake is captured.
     *
     * \sa handshake_captured_callback_type
     * \param callback The new callback to be set
     */
    void handshake_captured_callback(const handshake_captured_callback_type& callback);

    /**
     * \brief Sets the access point found callback
     * 
     * This callback will be executed every time a new access point is found, that's
     * advertising an SSID added when calling add_ap_data.
     *
     * \sa ap_found_callback_type
     * \param callback The new callback to be set
     */
    void ap_found_callback(const ap_found_callback_type& callback);

    #endif // TINS_HAVE_WPA2_CALLBACKS

    /**
     * \brief Getter for the keys on this decrypter
     *
     * The returned map will be populated every time a new, complete, handshake
     * is captured. 
     *
     * \return The WPA2Decrypter keys map.
     */
    const keys_map& get_keys() const;
private:
    typedef std::map<std::string, WPA2::SupplicantData> pmks_map;
    typedef std::map<address_type, WPA2::SupplicantData> bssids_map;
    
    void try_add_keys(const Dot11Data& dot11, const RSNHandshake& hs);
    addr_pair make_addr_pair(const address_type& addr1, const address_type& addr2) {
        return (addr1 < addr2) ? 
            std::make_pair(addr1, addr2) :
            std::make_pair(addr2, addr1);
    }
    addr_pair extract_addr_pair(const Dot11Data& dot11);
    addr_pair extract_addr_pair_dst(const Dot11Data& dot11);
    bssids_map::const_iterator find_ap(const Dot11Data& dot11);
    void add_access_point(const std::string& ssid, const address_type& addr);

    RSNHandshakeCapturer capturer_;
    pmks_map pmks_;
    bssids_map aps_;
    keys_map keys_;
    #ifdef TINS_HAVE_WPA2_CALLBACKS
        handshake_captured_callback_type handshake_captured_callback_;
        ap_found_callback_type ap_found_callback_;
    #endif // TINS_HAVE_WPA2_CALLBACKS
};
#endif // TINS_HAVE_WPA2_DECRYPTION

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
    DecrypterProxy(const functor_type& func, 
      const decrypter_type& decr = decrypter_type());
    
    /**
     * \brief Retrieves a reference to the decrypter object.
     */
    decrypter_type& decrypter();
    
    /**
     * \brief Retrieves a const reference to the decrypter object.
     */
    const decrypter_type& decrypter() const;
    
    /**
     * \brief The operator() which decrypts packets and forwards
     * them to the functor.
     */
    bool operator() (PDU& pdu);
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
void rc4(ForwardIterator start, ForwardIterator end, RC4Key& key, OutputIterator output);

/**
 * \brief Wrapper function to create a DecrypterProxy using a 
 * WEPDecrypter as the Decrypter template parameter.
 * 
 * \param functor The functor to be forwarded to the DecrypterProxy
 * constructor.
 */
template<typename Functor>
DecrypterProxy<Functor, WEPDecrypter> make_wep_decrypter_proxy(const Functor& functor);

#ifdef TINS_HAVE_WPA2_DECRYPTION
/**
 * \brief Wrapper function to create a DecrypterProxy using a 
 * WPA2Decrypter as the Decrypter template parameter.
 * 
 * \param functor The functor to be forwarded to the DecrypterProxy
 * constructor.
 */
template<typename Functor>
DecrypterProxy<Functor, WPA2Decrypter> make_wpa2_decrypter_proxy(const Functor& functor) {
    return DecrypterProxy<Functor, WPA2Decrypter>(functor);
}
#endif // TINS_HAVE_WPA2_DECRYPTION

// Implementation section

// DecrypterProxy

template<typename Functor, typename Decrypter>
DecrypterProxy<Functor, Decrypter>::DecrypterProxy(const functor_type& func,
                                                   const decrypter_type& decr) 
: functor_(func), decrypter_(decr) {
    
}

template<typename Functor, typename Decrypter>
typename DecrypterProxy<Functor, Decrypter>::decrypter_type &
  DecrypterProxy<Functor, Decrypter>::decrypter() {
    return decrypter_;
}

template<typename Functor, typename Decrypter>
const typename DecrypterProxy<Functor, Decrypter>::decrypter_type &
  DecrypterProxy<Functor, Decrypter>::decrypter() const {
    return decrypter_;
}

template<typename Functor, typename Decrypter>
bool DecrypterProxy<Functor, Decrypter>::operator() (PDU& pdu) {
    return decrypter_.decrypt(pdu) ? functor_(pdu) : true;
}

template<typename Functor>
DecrypterProxy<Functor, WEPDecrypter> make_wep_decrypter_proxy(const Functor& functor) {
    return DecrypterProxy<Functor, WEPDecrypter>(functor);
}

// RC4 stuff

template<typename ForwardIterator>
RC4Key::RC4Key(ForwardIterator start, ForwardIterator end) {
    for (size_t i = 0; i < data_size; ++i) {
        data[i] = static_cast<uint8_t>(i);
    }
    size_t j = 0;
    ForwardIterator iter = start;
    for (size_t i = 0; i < data_size; ++i) {
        j = (j + data[i] + *iter++) % 256;
        if(iter == end) {
            iter = start;
        }
        std::swap(data[i], data[j]);
    }
}

template<typename ForwardIterator, typename OutputIterator>
void rc4(ForwardIterator start, ForwardIterator end, RC4Key& key, OutputIterator output) {
    size_t i = 0, j = 0;
    while (start != end) {
        i = (i + 1) % RC4Key::data_size;
        j = (j + key.data[i]) % RC4Key::data_size;
        std::swap(key.data[i], key.data[j]);
        *output++ = *start++ ^ key.data[(key.data[i] + key.data[j]) % RC4Key::data_size];
    }
}

} // Crypto
} // Tins

#endif // TINS_CRYPTO_H
