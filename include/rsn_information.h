/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef TINS_RSN_INFORMATION
#define TINS_RSN_INFORMATION

#include <stdint.h>
#include <vector>
#include "endianness.h"

namespace Tins{
    /**
     * \brief Class that models the RSN information structure.
     */
    class RSNInformation {
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
         * \brief Creates an instance of RSNInformation.
         *
         * By default, the version is set to 1.
         */
        RSNInformation();
        
        /**
         * \brief Constructor from buffer.
         * 
         * \param buffer The buffer from which this object will be constructed.
         * \param total_sz The total size of the buffer.
         */
        RSNInformation(const uint8_t *buffer, uint32_t total_sz);

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
         * \brief Adds a akm suite.
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
        CypherSuites group_suite() const { return _group_suite; }

        /**
         * \brief Getter for the version field.
         * \return The version field.
         */
        uint16_t version() const { return Endian::le_to_host(_version); }
        
        /**
         * \brief Getter for the capabilities field.
         * \return The version field.
         */
        uint16_t capabilities() const { return Endian::le_to_host(_capabilities); }

        /**
         * \brief Getter for the pairwise cypher suite list.
         * \return A list of pairwise cypher suites.
         */
        const cyphers_type &pairwise_cyphers() const { return _pairwise_cyphers; }

        /**
         * \brief Getter for the akm suite list.
         * \return A list of akm suites.
         */
        const akm_type &akm_cyphers() const { return _akm_cyphers; }

        /**
         * \brief Serializes this object.
         * \return The result of the serialization. 
         */
         serialization_type serialize() const;
    private:
        uint16_t _version, _capabilities;
        CypherSuites _group_suite;
        akm_type _akm_cyphers;
        cyphers_type _pairwise_cyphers;
    };
} // namespace Tins

#endif // TINS_RSN_INFORMATION
