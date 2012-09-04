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

#ifndef TINS_IEEE8022_H
#define TINS_IEEE8022_H

#include <list>
#include <utility>
#include <stdint.h>
#include "pdu.h"
#include "endianness.h"

namespace Tins {

    /**
     * \brief Class representing a LLC frame.
     *
     * This PDU follows the standard LLC frame described in the IEEE 802.2 specs.
     */
    class LLC : public PDU {
    public:
        /**
         * \brief This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::LLC;

    	/**
         * \brief Represents the LLC global DSAP address.
         */
        static const uint8_t GLOBAL_DSAP_ADDR;
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
         * \brief Creates an instance of LLC
         * \param child The child PDU.(optional)
         */
    	LLC(PDU *child = 0);

    	/**
    	 * \brief Creates an instance of LLC, setting the dsap and ssap.
    	 * The control field is set all to 0.
    	 * @param dsap The dsap value to be set.
    	 * @param ssap The ssap value to be set.
    	 */
    	LLC(uint8_t dsap, uint8_t ssap, PDU* child = 0);

        /**
         * \brief Constructor which creates a LLC object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
    	LLC(const uint8_t *buffer, uint32_t total_sz);

        /**
         * \brief Copy constructor.
         */
    	LLC(const LLC &other);

        /**
         * \brief Copy assignment operator.
         */
    	LLC &operator= (const LLC &other);

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
		void add_xid_information(uint8_t xid_id, uint8_t llc_type_class, uint8_t receive_window);

		//TODO: Add Acknowledged connectionless information

        /* Getters */

		/**
		 * \brief Getter for the group destination bit.
		 * \return Whether the group bit is set or not.
		 */
		bool group() {return _header.dsap & 0x01; }

		/**
		 * \brief Getter for the dsap field.
		 * \return The dsap field value
		 */
		uint8_t dsap() {return _header.dsap; }

		/**
		 * \brief Getter for the response bit.
		 * \return Whether the response bit is set or not.
		 */
		bool response() {return (_header.ssap & 0x01); }

		/**
		 * \brief Getter for the ssap field.
		 * \return The ssap field.
		 */
		uint8_t ssap() {return _header.ssap; }

		/**
		 * \brief Getter for the LLC frame format type.
		 * \return The LLC frame format.
		 */
		uint8_t type() {return _type; }

		/**
		 * \brief Getter for sender send sequence number.
		 *
		 * \return The sender send sequence number if format is INFORMATION else 0.
		 */
		uint8_t send_seq_number() {
			return (type() == INFORMATION) ? (control_field.info.send_seq_num) : 0;
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
			if (type() == SUPERVISORY)
				return control_field.super.supervisory_func;
			return 0;
		}

		/**
		 * \brief Getter for the modifier function field.
		 *
		 * \return The modifier function if format is UNNUMBERED else 0.
		 */
		uint8_t modifier_function() {
			if (type() == UNNUMBERED)
				return (control_field.unnumbered.mod_func1 << 3) + control_field.unnumbered.mod_func2;
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
        PDUType pdu_type() const { return PDU::LLC; }

        /**
		 * \brief Delete all the information fields added.
		 */
		void clear_information_fields();

        /**
         * \brief Clones this PDU.
         *
         * \sa PDU::clone_pdu
         */
        PDU *clone_pdu() const;
    private:
        struct llchdr {
            uint8_t dsap;
            uint8_t ssap;
        } __attribute__((__packed__));

        #if TINS_IS_LITTLE_ENDIAN
            struct info_control_field {
                uint16_t
                            type_bit:1,
                            send_seq_num:7,
                            poll_final_bit:1,
                            recv_seq_num:7;
            } __attribute__((__packed__));

            struct super_control_field {
                uint16_t	type_bit:2,
                            supervisory_func:2,
                            unused:4,
                            poll_final_bit:1,
                            recv_seq_num:7;
            } __attribute__((__packed__));

            struct un_control_field {
                uint8_t		type_bits:2,
                            mod_func1:2,
                            poll_final_bit:1,
                            mod_func2:3;
            } __attribute__((__packed__));
        #elif TINS_IS_BIG_ENDIAN
            struct info_control_field {
                uint16_t    send_seq_num:7,
                            type_bit:1,
                            recv_seq_num:7,
                            poll_final_bit:1;
            } __attribute__((__packed__));

            struct super_control_field {
                uint16_t	unused:4,
                            supervisory_func:2,
                            type_bit:2,
                            recv_seq_num:7,
                            poll_final_bit:1;
            } __attribute__((__packed__));

            struct un_control_field {
                uint8_t		mod_func2:3,
                            poll_final_bit:1,
                            mod_func1:2,
                            type_bits:2;
            } __attribute__((__packed__));

        #endif

        void copy_fields(const LLC *other);
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        llchdr _header;
        uint8_t control_field_length;
        union {
        	info_control_field info;
        	super_control_field super;
        	un_control_field unnumbered;
        } control_field;
        Format _type;
        uint8_t information_field_length;
        std::list<std::pair<uint8_t,uint8_t*> > information_fields;
    };

};

#endif // TINS_IEEE8022_H
