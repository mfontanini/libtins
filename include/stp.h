/*
 * Copyright (c) 2012, Nasel
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

#include "pdu.h"
#include "endianness.h"
#include "small_uint.h"

namespace Tins {
class STP : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::STP;

    /**
     * \brief Default constructor.
     */
    STP();
    
    /**
     * \brief Constructor which constructs an STP object from a buffer 
     * and adds all identifiable PDUs found in the buffer as children 
     * of this one.
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    STP(const uint8_t *buffer, uint32_t total_sz);

    // Getters

    /**
     *  \brief Getter for the proto_id field.
     *  \return The stored proto_id field value.
     */
    uint16_t proto_id() const {
        return Endian::be_to_host(_header.proto_id);
    }

    /**
     *  \brief Getter for the proto_version field.
     *  \return The stored proto_version field value.
     */
    uint8_t proto_version() const {
        return _header.proto_version;
    }

    /**
     *  \brief Getter for the bpdu_type field.
     *  \return The stored bpdu_type field value.
     */
    uint8_t bpdu_type() const {
        return _header.bpdu_type;
    }

    /**
     *  \brief Getter for the bpdu_flags field.
     *  \return The stored bpdu_flags field value.
     */
    uint8_t bpdu_flags() const {
        return _header.bpdu_flags;
    }

    /**
     *  \brief Getter for the root_path_cost field.
     *  \return The stored root_path_cost field value.
     */
    uint32_t root_path_cost() const {
        return Endian::be_to_host(_header.root_path_cost);
    }

    /**
     *  \brief Getter for the port_id field.
     *  \return The stored port_id field value.
     */
    uint16_t port_id() const {
        return Endian::be_to_host(_header.port_id);
    }

    /**
     *  \brief Getter for the msg_age field.
     *  \return The stored msg_age field value.
     */
    uint16_t msg_age() const {
        return Endian::be_to_host(_header.msg_age) / 256;
    }

    /**
     *  \brief Getter for the max_age field.
     *  \return The stored max_age field value.
     */
    uint16_t max_age() const {
        return Endian::be_to_host(_header.max_age) / 256;
    }

    /**
     *  \brief Getter for the hello_time field.
     *  \return The stored hello_time field value.
     */
    uint16_t hello_time() const {
        return Endian::be_to_host(_header.hello_time) / 256;
    }

    /**
     *  \brief Getter for the fwd_delay field.
     *  \return The stored fwd_delay field value.
     */
    uint16_t fwd_delay() const {
        return Endian::be_to_host(_header.fwd_delay) / 256;
    }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \sa PDU::clone
     */
    STP *clone() const {
        return new STP(*this);
    }
    
    /**
    * \brief Returns the header size.
    *
    * This metod overrides PDU::header_size. \sa PDU::header_size
    */
    uint32_t header_size() const;

    // Setters

    /**
     *  \brief Setter for the proto_id field.
     *  \param new_proto_id The new proto_id field value.
     */
    void proto_id(uint16_t new_proto_id);

    /**
     *  \brief Setter for the proto_version field.
     *  \param new_proto_version The new proto_version field value.
     */
    void proto_version(uint8_t new_proto_version);

    /**
     *  \brief Setter for the bpdu_type field.
     *  \param new_bpdu_type The new bpdu_type field value.
     */
    void bpdu_type(uint8_t new_bpdu_type);

    /**
     *  \brief Setter for the bpdu_flags field.
     *  \param new_bpdu_flags The new bpdu_flags field value.
     */
    void bpdu_flags(uint8_t new_bpdu_flags);

    /**
     *  \brief Setter for the root_path_cost field.
     *  \param new_root_path_cost The new root_path_cost field value.
     */
    void root_path_cost(uint32_t new_root_path_cost);

    /**
     *  \brief Setter for the port_id field.
     *  \param new_port_id The new port_id field value.
     */
    void port_id(uint16_t new_port_id);

    /**
     *  \brief Setter for the msg_age field.
     *  \param new_msg_age The new msg_age field value.
     */
    void msg_age(uint16_t new_msg_age);

    /**
     *  \brief Setter for the max_age field.
     *  \param new_max_age The new max_age field value.
     */
    void max_age(uint16_t new_max_age);

    /**
     *  \brief Setter for the hello_time field.
     *  \param new_hello_time The new hello_time field value.
     */
    void hello_time(uint16_t new_hello_time);

    /**
     *  \brief Setter for the fwd_delay field.
     *  \param new_fwd_delay The new fwd_delay field value.
     */
    void fwd_delay(uint16_t new_fwd_delay);
private:
    TINS_BEGIN_PACK
    struct pvt_bpdu_id {
        #if TINS_IS_LITTLE_ENDIAN 
            // fixme
            uint16_t priority:4,
                    ext_id:12;
        #else
            uint16_t priority:4,
                    ext_id:12;
        #endif
        uint8_t id[6];
    } TINS_END_PACK;

    TINS_BEGIN_PACK
    struct stphdr {
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
    
    void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
    
    stphdr _header;
};
}

#endif // TINS_STP_H
