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

#ifndef __IEEE8022_H
#define __IEEE8022_H


#include <stdint.h>
#include "pdu.h"
#include "utils.h"

namespace Tins {

    /**
     * \brief Class representing a SNAP frame.
     *
     * Note that this PDU contains the 802.3 LLC structure + SNAP frame.
     * So far only unnumbered information structure is supported.
     */
    class LLC : public PDU {
    public:

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
        	XID = 0xAC,
        	TEST = 0xE0,
        	SABME = 0x6C,
        	DISC = 0x40,
        	UA = 0x60,
        	DM = 0x0C,
        	FRMR = 0x84
        };

        /**
         * \brief LLC Supervisory functions
         */
        enum SupervisoryFunctions {
        	RECEIVE_READY = 0x00,
        	REJECT = 0x08,
        	RECEIVE_NOT_READY = 0x04
        };

        /**
         * \brief Creates an instance of LLC
         * This constructor sets the dsap and ssap fields to 0xaa, and
         * the id field to 3.
         * \param child The child PDU.(optional)
         */
    	LLC(PDU *child = 0);

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
    	LLC(const SNAP &other);

        /**
         * \brief Copy assignment operator.
         */
    	LLC &operator= (const SNAP &other);

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
		 * \brief Setter for the command bit.
		 * \param value The value to be set.
		 */
		void command(bool value);

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
		 * \brief Setter for the poll flag.
		 * \param value Bool indicating the value of the flag.
		 */
		void poll(bool value);

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
         * \brief Returns the SNAP frame's header length.
         *
         * \return The header's size.
         * \sa PDU::header_size()
         */
        uint32_t header_size() const;

        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::SNAP; }

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

        void copy_fields(const LLC *other);
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        llchdr _snap;
        uint8_t control_field_length;
        uint16_t control_field;
        uint8_t information_field_length;
        uint8_t* information_field;
    };

};

#endif
