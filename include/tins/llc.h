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

#ifndef TINS_IEEE8022_H
#define TINS_IEEE8022_H

#include <vector>
#include <stdint.h>
#include <tins/macros.h>
#include <tins/pdu.h>
#include <tins/endianness.h>

namespace Tins {

/**
 * \class LLC
 * \brief Representing a LLC frame.
 *
 * This PDU follows the standard LLC frame described in the IEEE 802.2 specs.
 */
class TINS_API LLC : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::LLC;

	/**
     * \brief Represents the LLC global DSAP address.
     */
    static const uint8_t GLOBAL_DSAP_ADDR;
    
    /**
     * \brief Represents the LLC NULL address.
     */
    static const uint8_t NULL_ADDR;

    /**
     * \brief LLC Format flags.
     */
    enum Format {
        INFORMATION = 0,
        SUPERVISORY = 1,
        UNNUMBERED = 3
    };

    /**
     * \brief LLC Modifier functions.
     */
    enum ModifierFunctions {
    	UI = 0x00,
    	XID = 0x1D,
    	TEST = 0x07,
    	SABME = 0x1E,
    	DISC = 0x02,
    	UA = 0x06,
    	DM = 0x18,
    	FRMR = 0x11
    };

    /**
     * \brief LLC Supervisory functions
     */
    enum SupervisoryFunctions {
    	RECEIVE_READY = 0,
    	REJECT = 2,
    	RECEIVE_NOT_READY = 1
    };

    /**
     * \brief Default constructor.
     */
	LLC();

	/**
	 * \brief Constructs an instance of LLC, setting the dsap and ssap.
	 * The control field is set to 0.
	 * \param dsap The dsap value to be set.
	 * \param ssap The ssap value to be set.
	 */
	LLC(uint8_t dsap, uint8_t ssap);

    /**
     * \brief Constructs a LLC object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this one.
     * 
     * If there is not enough size for a LLC header, a malformed_packet
     * exception is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
	LLC(const uint8_t* buffer, uint32_t total_sz);

    /* Setters */

	/**
	 * \brief Setter for the group destination bit.
	 * \param value The value to be set.
	 */
    void group(bool value);

    /**
	 * \brief Setter for the dsap field.
	 * \param new_dsap The new dsap field.
	 */
	void dsap(uint8_t new_dsap);

	/**
	 * \brief Setter for the response bit.
	 * \param value The value to be set.
	 */
	void response(bool value);

	/**
	 * \brief Setter for the ssap field.
	 * \param new_ssap The new ssap field.
	 */
	void ssap(uint8_t new_ssap);

	/**
	 * \brief Setter for the LLC frame format type.
	 * \param type The LLC frame format to set.
	 */
	void type(Format type);

	/**
	 * \brief Setter for sender send sequence number.
	 * 	Only applied if format is INFORMATION.
	 * \param seq_number New sender send sequence number to be set.
	 */
	void send_seq_number(uint8_t seq_number);

	/**
	 * \brief Setter for sender receive sequence number.
	 * 	Only applied if format is INFORMATION or SUPERVISORY.
	 * \param seq_number New sender receive sequence number to be set.
	 */
	void receive_seq_number(uint8_t seq_number);

	/**
	 * \brief Setter for the poll/final flag.
	 * \param value Bool indicating the value of the flag.
	 */
	void poll_final(bool value);

	/**
	 * \brief Setter for the supervisory function.
	 * Only applied if format is SUPERVISORY.
	 * \param new_func Value to set on the supervisory function field.
	 */
	void supervisory_function(SupervisoryFunctions new_func);

	/**
	 * \brief Setter for the modifier function field.
	 * Only applied if format is UNNUMBERED.
	 * \param modifier_func Value to set on the modifier function field.
	 */
	void modifier_function(ModifierFunctions mod_func);

	/**
	 * \brief Add a xid information field.
	 * Only applied if format is UNNUMBERED and function is XID.
	 * \param xid_id XID information of the MAC sublayer.
	 * \param llc_type_class Value to set the llc_type_class field.
	 * \param receive_window XID sender's receive window size.
	 */
	void add_xid_information(uint8_t xid_id, 
                             uint8_t llc_type_class,
                             uint8_t receive_window);

	//TODO: Add Acknowledged connectionless information

    /* Getters */

	/**
	 * \brief Getter for the group destination bit.
	 * \return Whether the group bit is set or not.
	 */
	bool group() {
        return header_.dsap & 0x01;
    }

	/**
	 * \brief Getter for the dsap field.
	 * \return The dsap field value
	 */
	uint8_t dsap() {
        return header_.dsap;
    }

	/**
	 * \brief Getter for the response bit.
	 * \return Whether the response bit is set or not.
	 */
	bool response() {
        return (header_.ssap & 0x01);
    }

	/**
	 * \brief Getter for the ssap field.
	 * \return The ssap field.
	 */
	uint8_t ssap() {
        return header_.ssap;
    }

	/**
	 * \brief Getter for the LLC frame format type.
	 * \return The LLC frame format.
	 */
	uint8_t type() {
        return static_cast<uint8_t>(type_);
    }

	/**
	 * \brief Getter for sender send sequence number.
	 *
	 * \return The sender send sequence number if format is INFORMATION else 0.
	 */
	uint8_t send_seq_number() {
		return static_cast<uint8_t>((type() == INFORMATION) ? (control_field.info.send_seq_num) : 0);
	}

	/**
	 * \brief Getter for sender receive sequence number.
	 *
	 * \return 	The sender receive sequence number if format is
	 * 			INFORMATION or SUPERVISORY else 0.
	 */
	uint8_t receive_seq_number() {
		switch (type()) {
			case INFORMATION:
				return control_field.info.recv_seq_num;
			case SUPERVISORY:
				return control_field.super.recv_seq_num;
			case UNNUMBERED:
				return 0;
            default:
                return 0;
		}
	}

	/**
	 * \brief Getter for the poll/final flag.
	 * \return Whether the poll/final flag is set.
	 */
	bool poll_final() {
		switch (type()) {
			case UNNUMBERED:
				return control_field.unnumbered.poll_final_bit;
			case INFORMATION:
				return control_field.info.poll_final_bit;
			case SUPERVISORY:
				return control_field.super.poll_final_bit;
            default:
                return false;
		}
	}

	/**
	 * \brief Getter for the supervisory function.
	 *
	 * \return The supervisory function if format is SUPERVISORY else 0.
	 */
	uint8_t supervisory_function() {
		if (type() == SUPERVISORY) {
			return control_field.super.supervisory_func;
        }
		return 0;
	}

	/**
	 * \brief Getter for the modifier function field.
	 *
	 * \return The modifier function if format is UNNUMBERED else 0.
	 */
	uint8_t modifier_function() {
		if (type() == UNNUMBERED) {
			return (control_field.unnumbered.mod_func1 << 3) + control_field.unnumbered.mod_func2;
        }
		return 0;
	}

    /**
     * \brief Returns the LLC frame's header length.
     *
     * \return The header's size.
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
	 * \brief Delete all the information fields added.
	 */
	void clear_information_fields();

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    LLC* clone() const {
        return new LLC(*this);
    }
private:
    TINS_BEGIN_PACK
    struct llchdr {
        uint8_t dsap;
        uint8_t ssap;
    } TINS_END_PACK;

    #if TINS_IS_LITTLE_ENDIAN
        TINS_BEGIN_PACK
        struct info_control_field {
            uint16_t
                        type_bit:1,
                        send_seq_num:7,
                        poll_final_bit:1,
                        recv_seq_num:7;
        } TINS_END_PACK;

        TINS_BEGIN_PACK
        struct super_control_field {
            uint16_t	type_bit:2,
                        supervisory_func:2,
                        unused:4,
                        poll_final_bit:1,
                        recv_seq_num:7;
        } TINS_END_PACK;

        TINS_BEGIN_PACK
        struct un_control_field {
            uint8_t		type_bits:2,
                        mod_func1:2,
                        poll_final_bit:1,
                        mod_func2:3;
        } TINS_END_PACK;
    #elif TINS_IS_BIG_ENDIAN
        TINS_BEGIN_PACK
        struct info_control_field {
            uint16_t    send_seq_num:7,
                        type_bit:1,
                        recv_seq_num:7,
                        poll_final_bit:1;
        } TINS_END_PACK;

        TINS_BEGIN_PACK
        struct super_control_field {
            uint16_t	unused:4,
                        supervisory_func:2,
                        type_bit:2,
                        recv_seq_num:7,
                        poll_final_bit:1;
        } TINS_END_PACK;

        TINS_BEGIN_PACK
        struct un_control_field {
            uint8_t		mod_func2:3,
                        poll_final_bit:1,
                        mod_func1:2,
                        type_bits:2;
        } TINS_END_PACK;
    #endif
    
    typedef std::vector<uint8_t> field_type;
    typedef std::vector<field_type> field_list;

    void write_serialization(uint8_t* buffer, uint32_t total_sz);

    llchdr header_;
    uint8_t control_field_length_;
    union {
    	info_control_field info;
    	super_control_field super;
    	un_control_field unnumbered;
    } control_field;
    Format type_;
    uint8_t information_field_length_;
    field_list information_fields_;
};

} // Tins

#endif // TINS_IEEE8022_H
