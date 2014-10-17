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

#include "config.h"

#if !defined(TINS_HANDSHAKE_CAPTURER_H)  && defined(HAVE_DOT11)
#define TINS_HANDSHAKE_CAPTURER_H

#include <vector>
#include <map>
#include <utility>
#include "hw_address.h"
#include "eapol.h"

// .h
namespace Tins {
    /**
     * \brief Generic EAPOL handshake.
     *
     * Stores both the client and supplicant addresses, as well as 
     * all of the EAPOL packets used during the handshake.
     */
    template<typename T>
    class EAPOLHandshake {
    public:
        typedef std::vector<T> container_type;
        typedef HWAddress<6> address_type;
        
        /**
         * \brief Default constructor.
         */
        EAPOLHandshake() { }

        /**
         * Constructs an EAPOLHandshake object.
         * 
         * \param client_address The client address.
         * \param supplicant_address The supplicant address.
         * \param cont The container that holds the EAPOL packets used
         * in the handshake.
         */
        EAPOLHandshake(const address_type &client_address, 
          const address_type &supplicant_address, const container_type &cont) 
        : cl_address_(client_address), suppl_address_(supplicant_address), 
        handshake_(cont) 
        {
            
        }
        
        /**
         * \return const address_type&
         */
        const address_type &client_address() const {
            return cl_address_;
        }
        
        /**
         * \return const address_type&
         */
        const address_type &supplicant_address() const {
            return suppl_address_;
        }
        
        /**
         * \return const container_type&
         */
        const container_type &handshake() const {
            return handshake_;
        }
    private:
        address_type cl_address_, suppl_address_;
        container_type handshake_;
    };
    
    /**
     * The type used to store RSN handshakes.
     */
    typedef EAPOLHandshake<RSNEAPOL> RSNHandshake;
    
    /**
     * Captures 802.1X RSN handshakes.
     */
    class RSNHandshakeCapturer {
    public:
        /**
         * The type of handshakes that will be captured.
         */
        typedef RSNHandshake handshake_type;

        /**
         * The type in which all of the captured handshakes
         * will be stored.
         */
        typedef std::vector<handshake_type> handshakes_type;
        
        /**
         * \brief Processes a packet.
         * 
         * This will fetch the RSNEAPOL layer, if any, and store
         * it in an intermediate storage. When a handshake is 
         * completed, it will be stored separately. 
         *
         * \sa RSNHandshakeCapturer::handshakes
         */
        bool process_packet(const PDU &pdu);

        /**
         * \brief Retrieves the completed handshakes.
         *
         * This will return the handshakes that have been completed 
         * so far. A handshake is completed when the 4-way handshake
         * is captured.
         *
         * \sa RSNHandshakeCapturer::clear_handshakes
         */
        const handshakes_type &handshakes() const {
            return completed_handshakes_;
        }

        /**
         * \brief Clears the completed handshakes.
         *
         * Since completed handshakes are stored in a std::vector,
         * it is advisable to remove all of them once they have been 
         * processed.
         */
        void clear_handshakes() {
            completed_handshakes_.clear();
        }
    private:
        typedef handshake_type::address_type address_type;
        typedef handshake_type::container_type eapol_list;
        typedef std::map<std::pair<address_type, address_type>, eapol_list> handshake_map;
    
        bool do_insert(const handshake_map::key_type &key, const RSNEAPOL *eapol, 
          size_t expected);
    
        handshake_map handshakes_;
        handshakes_type completed_handshakes_;
    };
}

#endif // TINS_HANDSHAKE_CAPTURER_H
