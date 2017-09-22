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

#ifndef TINS_STP_H
#define TINS_STP_H

#include <tins/pdu.h>
#include <tins/macros.h>
#include <tins/endianness.h>
#include <tins/hw_address.h>
#include <tins/small_uint.h>

namespace Tins {
/**
 * \class STP
 * \brief Represents a Spanning Tree Protocol PDU.
 */
class TINS_API STP : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::STP;
    
    /**
     * The type used to store BPDU identifier addresses.
     */
    typedef HWAddress<6> address_type;
    
    /**
     * The type used to store the BPDU identifiers.
     */
    struct bpdu_id_type {
        small_uint<4> priority;
        small_uint<12> ext_id;
        address_type id;
        
        bpdu_id_type(small_uint<4> priority=0, small_uint<12> ext_id=0, 
            const address_type& id=address_type())
        : priority(priority), ext_id(ext_id), id(id) { }
    };

    /**
     * \brief Default constructor.
     */
    STP();
    
    /**
     * \brief Constructs a STP object from a buffer.
     * 
     * If there is not enough size for a STP header, a malformed_packet
     * exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    STP(const uint8_t* buffer, uint32_t total_sz);

    // Getters

    /**
     *  \brief Getter for the Protocol ID field.
     *  \return The stored Protocol ID field value.
     */
    uint16_t proto_id() const {
        return Endian::be_to_host(header_.proto_id);
    }

    /**
     *  \brief Getter for the Protocol Version field.
     *  \return The stored Protocol Version field value.
     */
    uint8_t proto_version() const {
        return header_.proto_version;
    }

    /**
     *  \brief Getter for the BDU Type field.
     *  \return The stored BDU Type field value.
     */
    uint8_t bpdu_type() const {
        return header_.bpdu_type;
    }

    /**
     *  \brief Getter for the BDU Flags field.
     *  \return The stored BDU Flags field value.
     */
    uint8_t bpdu_flags() const {
        return header_.bpdu_flags;
    }

    /**
     *  \brief Getter for the Root Path Cost field.
     *  \return The stored Root Path Cost field value.
     */
    uint32_t root_path_cost() const {
        return Endian::be_to_host(header_.root_path_cost);
    }

    /**
     *  \brief Getter for the Port ID field.
     *  \return The stored Port ID field value.
     */
    uint16_t port_id() const {
        return Endian::be_to_host(header_.port_id);
    }

    /**
     *  \brief Getter for the Message Age field.
     *  \return The stored Message Age field value.
     */
    uint16_t msg_age() const {
        return Endian::be_to_host(header_.msg_age) / 256;
    }

    /**
     *  \brief Getter for the Maximum Age field.
     *  \return The stored Maximum Age field value.
     */
    uint16_t max_age() const {
        return Endian::be_to_host(header_.max_age) / 256;
    }

    /**
     *  \brief Getter for the Hello Time field.
     *  \return The stored Hello Time field value.
     */
    uint16_t hello_time() const {
        return Endian::be_to_host(header_.hello_time) / 256;
    }

    /**
     *  \brief Getter for the Forward Delay field.
     *  \return The stored Forward Delay field value.
     */
    uint16_t fwd_delay() const {
        return Endian::be_to_host(header_.fwd_delay) / 256;
    }
    
    /**
     *  \brief Getter for the Root ID field.
     *  \return The stored Root ID field value.
     */
    bpdu_id_type root_id() const;
    
    /**
     *  \brief Getter for the Bridge ID field.
     *  \return The stored Bridge ID field value.
     */
    bpdu_id_type bridge_id() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \sa PDU::clone
     */
    STP* clone() const {
        return new STP(*this);
    }
    
    /**
    * \brief Returns the header size.
    *
    * This method overrides PDU::header_size. \sa PDU::header_size
    */
    uint32_t header_size() const;

    // Setters

    /**
     *  \brief Setter for the Protocol ID field.
     *  \param new_proto_id The new Protocol ID field value.
     */
    void proto_id(uint16_t new_proto_id);

    /**
     *  \brief Setter for the Protocol Version field.
     *  \param new_proto_version The new Protocol Version field value.
     */
    void proto_version(uint8_t new_proto_version);

    /**
     *  \brief Setter for the BPDU Type field.
     *  \param new_bpdu_type The new BPDU Type field value.
     */
    void bpdu_type(uint8_t new_bpdu_type);

    /**
     *  \brief Setter for the BPDU Flags field.
     *  \param new_bpdu_flags The new BPDU Flags field value.
     */
    void bpdu_flags(uint8_t new_bpdu_flags);

    /**
     *  \brief Setter for the Root Path Cost field.
     *  \param new_root_path_cost The new Root Path Cost field value.
     */
    void root_path_cost(uint32_t new_root_path_cost);

    /**
     *  \brief Setter for the Port ID field.
     *  \param new_port_id The new Port ID field value.
     */
    void port_id(uint16_t new_port_id);

    /**
     *  \brief Setter for the Message Age field.
     *  \param new_msg_age The new Message Age field value.
     */
    void msg_age(uint16_t new_msg_age);

    /**
     *  \brief Setter for the Maximum Age field.
     *  \param new_max_age The new Maximum Age field value.
     */
    void max_age(uint16_t new_max_age);

    /**
     *  \brief Setter for the Hello Time field.
     *  \param new_hello_time The new Hello Time field value.
     */
    void hello_time(uint16_t new_hello_time);

    /**
     *  \brief Setter for the Forward Delay field.
     *  \param new_fwd_delay The new Forward Delay field value.
     */
    void fwd_delay(uint16_t new_fwd_delay);
    
    /**
     *  \brief Setter for the Root ID field.
     *  \param new_fwd_delay The new Root ID field value.
     */
    void root_id(const bpdu_id_type& id);
    
    /**
     *  \brief Setter for the Bridge ID field.
     *  \param new_fwd_delay The new Bridge ID field value.
     */
    void bridge_id(const bpdu_id_type& id);
private:
    TINS_BEGIN_PACK
    struct pvt_bpdu_id {
        #if TINS_IS_LITTLE_ENDIAN 
            // fixme
            uint16_t ext_id:4,
                    priority:4,
                    ext_idL:8;
        #else
            uint16_t priority:4,
                    ext_id:12;
        #endif
        uint8_t id[6];
    } TINS_END_PACK;

    TINS_BEGIN_PACK
    struct stp_header {
        uint16_t proto_id;
        uint8_t proto_version;
        uint8_t bpdu_type;
        uint8_t bpdu_flags;
        pvt_bpdu_id root_id;
        uint32_t root_path_cost;
        pvt_bpdu_id bridge_id;
        uint16_t port_id;
        uint16_t msg_age;
        uint16_t max_age;
        uint16_t hello_time;
        uint16_t fwd_delay;
    } TINS_END_PACK;
    
    static bpdu_id_type convert(const pvt_bpdu_id& id);
    static pvt_bpdu_id convert(const bpdu_id_type& id);
    
    void write_serialization(uint8_t* buffer, uint32_t total_sz);
    
    stp_header header_;
};
}

#endif // TINS_STP_H
