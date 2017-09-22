/*
 * Copyright (c) 2017, Matias Fontanini
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

#include <tins/config.h>

#if !defined(TINS_DOT11_DOT11_BEACON_H) && defined(TINS_HAVE_DOT11)
#define TINS_DOT11_DOT11_BEACON_H

#include <tins/dot11/dot11_mgmt.h>
#include <tins/macros.h>

namespace Tins {

/**
 * \brief Represents an IEEE 802.11 Beacon.
 *
 */
class TINS_API Dot11Beacon : public Dot11ManagementFrame {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_BEACON;

    /**
     * \brief Constructor for creating a 802.11 Beacon.
     *
     * Constructs a 802.11 Beacon taking destination and source 
     * hardware address.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11Beacon(const address_type& dst_hw_addr = address_type(), 
                const address_type& src_hw_addr = address_type());

    /**
     * \brief Constructs a Dot11Beacon object from a buffer and adds
     * all identifiable PDUs found in the buffer as children of this 
     * one.
     *
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for the header in the buffer
     * or the input data is malformed, a malformed_packet exception 
     * is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11Beacon(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the timestamp field.
     *
     * \return The stored timestamp value.
     */
    uint64_t timestamp() const {
        return Endian::le_to_host(body_.timestamp);
    }

    /**
     * \brief Getter for the interval field.
     *
     * \return The stored interval value.
     */
    uint16_t interval() const {
        return Endian::le_to_host(body_.interval);
    }

    /**
     * \brief Getter for the Capabilities Information structure.
     *
     * \return A constant refereence to the stored Capabilities 
     * Information field.
     */
    const capability_information& capabilities() const {
        return body_.capability;
    }

    /**
     * \brief Getter for the Capabilities Information.
     *
     * \return A refereence to the stored Capabilities Information 
     * field.
     */
    capability_information& capabilities() {
        return body_.capability;
    }

    /**
     * \brief Setter for the timestamp field.
     *
     * \param new_timestamp The timestamp to be set.
     */
    void timestamp(uint64_t new_timestamp);

    /**
     * \brief Setter for the interval field.
     *
     * \param new_interval The interval to be set.
     */
    void interval(uint16_t new_interval);

    /**
     * \brief Returns the frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11Beacon* clone() const {
        return new Dot11Beacon(*this);
    }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }
private:
    TINS_BEGIN_PACK
    struct dot11_beacon_body {
        uint64_t timestamp;
        uint16_t interval;
        capability_information capability;
    } TINS_END_PACK;

    void write_fixed_parameters(Memory::OutputMemoryStream& stream);

    dot11_beacon_body body_;
};

} // namespace Tins

#endif // TINS_DOT11_DOT11_BEACON_H
