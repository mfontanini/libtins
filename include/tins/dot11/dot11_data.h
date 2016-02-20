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

#include "../config.h"

#if !defined(TINS_DOT11_DOT11_DATA_H) && defined(TINS_HAVE_DOT11)
#define TINS_DOT11_DOT11_DATA_H

#include "../dot11/dot11_base.h"
#include "../macros.h"

namespace Tins {

/**
 * \brief Represents an IEEE 802.11 data frame
 */
class TINS_API Dot11Data : public Dot11 {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_DATA;
    
    /**
     * \brief Constructor for creating a 802.11 Data frame.
     *
     * Constructs a 802.11 Data frame taking the
     * destination and source hardware addresses.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11Data(const address_type& dst_hw_addr = address_type(), 
              const address_type& src_hw_addr = address_type());
                
    /**
     * \brief Constructs a Dot11Data object from a buffer and adds 
     * all identifiable PDUs found in the buffer as children of 
     * this one.
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
    Dot11Data(const uint8_t* buffer, uint32_t total_sz);
    
    /**
     * \brief Getter for the second address.
     *
     * \return The stored second address.
     */
    address_type addr2() const {
        return ext_header_.addr2;
    }

    /**
     * \brief Getter for the third address.
     *
     * \return The stored third address.
     */
    address_type addr3() const {
        return ext_header_.addr3;
    }

    /**
     * \brief Getter for the fragment number field.
     *
     * \return The stored fragment number.
     */
    small_uint<4> frag_num() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return ext_header_.frag_seq & 0xf; 
        #else
        return (ext_header_.frag_seq >> 8) & 0xf; 
        #endif
    }

    /**
     * \brief Getter for the sequence number field.
     *
     * \return The stored sequence number.
     */
    small_uint<12> seq_num() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return (ext_header_.frag_seq >> 4) & 0xfff; 
        #else
        return (Endian::le_to_host<uint16_t>(ext_header_.frag_seq) >> 4) & 0xfff; 
        #endif
    }

    /**
     * \brief Getter for the fourth address.
     *
     * \return The fourth address.
     */
    address_type addr4() const {
        return addr4_;
    }

    /**
     * \brief Setter for the second address.
     *
     * \param new_addr2 The second address to be set.
     */
    void addr2(const address_type& new_addr2);

    /**
     * \brief Setter for the third address.
     *
     * \param new_addr3 The third address to be set.
     */
    void addr3(const address_type& new_addr3);

    /**
     * \brief Setter for the fragment number field.
     *
     * \param new_frag_num The fragment number to be set.
     */
    void frag_num(small_uint<4> new_frag_num);

    /**
     * \brief Setter for the sequence number field.
     *
     * \param new_seq_num The sequence number to be set.
     */
    void seq_num(small_uint<12> new_seq_num);

    /**
     * \brief Setter for the fourth address field.
     *
     * \param new_addr4 The fourth address to be set.
     */
    void addr4(const address_type& new_addr4);

    /**
     * \brief Retrieves the frame's source address.
     *
     * This is a wrapper over the addr* member functions which
     * takes into account the value of the FromDS and ToDS bits.
     *
     * If FromDS == ToDS == 1, the return value is not defined.
     */
    address_type src_addr() const {
        if (!from_ds() && !to_ds()) {
            return addr2();
        }
        if (!from_ds() && to_ds()) {
            return addr2();
        }
        return addr3();
    }

    /**
     * \brief Retrieves the frame's destination address.
     *
     * This is a wrapper over the addr* member functions which
     * takes into account the value of the FromDS and ToDS bits.
     *
     * If FromDS == ToDS == 1, the return value is not defined.
     */
    address_type dst_addr() const {
        if (!from_ds() && !to_ds()) {
            return addr1();
        }
        if (!from_ds() && to_ds()) {
            return addr3();
        }
        return addr1();
    }

    /**
     * \brief Retrieves the frame's BSSID address.
     *
     * This is a wrapper over the addr* member functions which
     * takes into account the value of the FromDS and ToDS bits.
     *
     * If FromDS == ToDS == 1, the return value is not defined.
     */
    address_type bssid_addr() const {
        if (!from_ds() && !to_ds()) {
            return addr3();
        }
        if (!from_ds() && to_ds()) {
            return addr1();
        }
        return addr2();
    }

    /**
     * \brief Returns the 802.11 frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11Data* clone() const {
        return new Dot11Data(*this);
    }
protected:
    TINS_BEGIN_PACK
    struct dot11_extended_header {
        uint8_t addr2[address_type::address_size];
        uint8_t addr3[address_type::address_size];
        uint16_t frag_seq;
    } TINS_END_PACK;
    
    struct no_inner_pdu { };
    Dot11Data(const uint8_t* buffer, uint32_t total_sz, no_inner_pdu);

    uint32_t init(const uint8_t* buffer, uint32_t total_sz);
    void write_ext_header(Memory::OutputMemoryStream& stream);
private:
    dot11_extended_header ext_header_;
    address_type addr4_;
};

class TINS_API Dot11QoSData : public Dot11Data {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_QOS_DATA;

    /**
     * \brief Constructor for creating a 802.11 QoS Data PDU
     *
     * Constructs a 802.11 QoS Data PDU taking the
     * destination and source hardware addresses.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11QoSData(const address_type& dst_hw_addr = address_type(), 
                 const address_type& src_hw_addr = address_type());

    /**
     * \brief Constructors Dot11QoSData object from a buffer and adds
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
    Dot11QoSData(const uint8_t* buffer, uint32_t total_sz);
    
    /**
     * \brief Getter for the QOS Control field.
     *
     * \return The stored QOS Control field value.
     */
    uint16_t qos_control() const {
        return Endian::le_to_host(qos_control_);
    }

    /**
     * \brief Setter for the QOS Control field.
     *
     * \param new_qos_control The QOS Control to be set.
     */
    void qos_control(uint16_t new_qos_control);

    /**
     * \brief Returns the frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11QoSData* clone() const {
        return new Dot11QoSData(*this);
    }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11Data::matches_flag(flag);
    }
private:
    void write_fixed_parameters(Memory::OutputMemoryStream& stream);

    uint16_t qos_control_;
};
}

#endif // TINS_DOT11_DOT11_DATA_H
