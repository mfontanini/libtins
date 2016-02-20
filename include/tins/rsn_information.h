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

#if !defined(TINS_RSN_INFORMATION) && defined(TINS_HAVE_DOT11)
#define TINS_RSN_INFORMATION

#include <stdint.h>
#include <vector>
#include "macros.h"
#include "endianness.h"

namespace Tins{
class Dot11;
template<typename T, typename U>
class PDUOption;
/**
 * \brief Class that models the RSN information structure.
 */
class TINS_API RSNInformation {
public:
    /**
     * \brief Enum that represents the different cypher suites.
     */
    enum CypherSuites {
        WEP_40  = 0x01ac0f00,
        TKIP    = 0x02ac0f00,
        CCMP    = 0x04ac0f00,
        WEP_104 = 0x05ac0f00
    };

    /**
     * \brief Enum that represents the different akm suites.
     */
    enum AKMSuites {
        PMKSA = 0x01ac0f00,
        PSK   = 0x02ac0f00
    };

    /**
     * The type used to store the cypher suites.
     */
    typedef std::vector<CypherSuites> cyphers_type;
    
    /**
     * The type used to store the AKM suites.
     */
    typedef std::vector<AKMSuites> akm_type;
    
    /**
     * The type returned on serialization.
     */
    typedef std::vector<uint8_t> serialization_type;

    /**
     * \brief Constructs an RSNInformation object.
     *
     * By default, the version is set to 1.
     */
    RSNInformation();
    
    /**
     * \brief Constructs an RSNInformation object from a 
     * serialization_type object.
     * 
     * \param buffer The buffer from which to construct this object.
     */
    RSNInformation(const serialization_type& buffer);
    
    /**
     * \brief Constructs a RSNInformation from a buffer.
     * 
     * If the input is malformed, a malformed_packet exception is
     * thrown.
     * 
     * \param buffer The buffer from which this object will be constructed.
     * \param total_sz The total size of the buffer.
     */
    RSNInformation(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Helper function to create a WPA2-PSK RSNInformation
     * \return An instance RSNInformation which contains information
     * for a WPA2-PSK AP.
     */
    static RSNInformation wpa2_psk();

    /**
     * \brief Adds a pairwise cypher suite.
     * \param cypher The pairwise cypher suite to be added.
     */
    void add_pairwise_cypher(CypherSuites cypher);

    /**
     * \brief Adds an akm suite.
     * \param akm The akm suite to be added.
     */
    void add_akm_cypher(AKMSuites akm);

    /**
     * \brief Sets the group suite cypher.
     * \param group The group suite cypher to be set.
     */
    void group_suite(CypherSuites group);

    /**
     * \brief Sets the version.
     * \param ver The version to be set.
     */
    void version(uint16_t ver);

    /**
     * \brief Sets the capabilities field.
     * \param cap The capabilities to be set.
     */
    void capabilities(uint16_t cap);

    /* Getters */

    /**
     * \brief Getter for the group suite field.
     * \return The group suite field.
     */
    CypherSuites group_suite() const { 
        return static_cast<CypherSuites>(Endian::le_to_host<uint32_t>(group_suite_)); 
    }

    /**
     * \brief Getter for the version field.
     * \return The version field.
     */
    uint16_t version() const {
        return Endian::le_to_host(version_);
    }
    
    /**
     * \brief Getter for the capabilities field.
     * \return The version field.
     */
    uint16_t capabilities() const {
        return Endian::le_to_host(capabilities_);
    }

    /**
     * \brief Getter for the pairwise cypher suite list.
     * \return A list of pairwise cypher suites.
     */
    const cyphers_type& pairwise_cyphers() const {
        return pairwise_cyphers_;
    }

    /**
     * \brief Getter for the akm suite list.
     * \return A list of akm suites.
     */
    const akm_type& akm_cyphers() const {
        return akm_cyphers_;
    }

    /**
     * \brief Serializes this object.
     * \return The result of the serialization. 
     */
     serialization_type serialize() const;
     
     /**
      * Constructs an RSNInformation object from a Dot11 tagged option.
      */
     static RSNInformation from_option(const PDUOption<uint8_t, Dot11>& opt);
private:
    void init(const uint8_t* buffer, uint32_t total_sz);

    uint16_t version_, capabilities_;
    CypherSuites group_suite_;
    akm_type akm_cyphers_;
    cyphers_type pairwise_cyphers_;
};
} // namespace Tins

#endif // TINS_RSN_INFORMATION
