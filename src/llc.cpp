/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2012 Nasel
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

#include <stdexcept>
#include <cstring>
#include <cassert>
#include <list>
#include <utility>

#include "pdu.h"
#include "llc.h"
#include "utils.h"
#include "rawpdu.h"

using std::list;
using std::pair;

namespace Tins {
const uint8_t LLC::GLOBAL_DSAP_ADDR = 0xFF;
const uint8_t LLC::NULL_ADDR = 0x00;

LLC::LLC(PDU *child) : PDU(0xff, child), _type(LLC::INFORMATION) {
	memset(&_header, 0, sizeof(llchdr));
	control_field_length = 2;
	memset(&control_field, 0, sizeof(control_field));
	information_field_length = 0;
}

LLC::LLC(uint8_t dsap, uint8_t ssap, PDU *child) : PDU(0xff, child), _type(LLC::INFORMATION) {
	_header.dsap = dsap;
	_header.ssap = ssap;
	control_field_length = 2;
	memset(&control_field, 0, sizeof(control_field));
	information_field_length = 0;
}

LLC::LLC(const uint8_t *buffer, uint32_t total_sz) : PDU(0xff) {
    // header + 1 info byte
	if(total_sz < sizeof(_header) + 1)
		throw std::runtime_error("Not enough size for a LLC header in the buffer.");
	std::memcpy(&_header, buffer, sizeof(_header));
	buffer += sizeof(_header);
	total_sz -= sizeof(_header);
	information_field_length = 0;
	if ((buffer[0] & 0x03) == LLC::UNNUMBERED) {
        if(total_sz < sizeof(un_control_field))
            throw std::runtime_error("Not enough size for a LLC header in the buffer.");
		type(LLC::UNNUMBERED);
		std::memcpy(&control_field.unnumbered, buffer, sizeof(un_control_field));
		buffer += sizeof(un_control_field);
		total_sz -= sizeof(un_control_field);
		//TODO: Create information fields if corresponding.
	}
	else {
        if(total_sz < sizeof(info_control_field))
            throw std::runtime_error("Not enough size for a LLC header in the buffer.");
		type((Format)(buffer[0] & 0x03));
		control_field_length = 2;
		std::memcpy(&control_field.info, buffer, sizeof(info_control_field));
		buffer += 2;
		total_sz -= 2;
	}
    if(total_sz > 0)
        inner_pdu(new Tins::RawPDU(buffer, total_sz));
}

LLC::LLC(const LLC &other): PDU(other) {
    copy_fields(&other);
}

LLC &LLC::operator= (const LLC &other) {
    copy_fields(&other);
    copy_inner_pdu(other);
    return *this;
}

void LLC::group(bool value) {
	if (value) {
		_header.dsap |= 0x01;
	}
	else {
		_header.dsap &= 0xFE;
	}
}

void LLC::dsap(uint8_t new_dsap) {
	_header.dsap = new_dsap;
}

void LLC::response(bool value) {
	if (value) {
		_header.ssap |= 0x01;
	}
	else {
		_header.ssap &= 0xFE;
	}
}

void LLC::ssap(uint8_t new_ssap) {
	_header.ssap = new_ssap;
}

void LLC::type(LLC::Format type) {
	_type = type;
	switch (type) {
		case LLC::INFORMATION:
			control_field_length = 2;
			control_field.info.type_bit = 0;
			break;
		case LLC::SUPERVISORY:
			control_field_length = 2;
			control_field.super.type_bit = 1;
			break;
		case LLC::UNNUMBERED:
			control_field_length = 1;
			control_field.unnumbered.type_bits = 3;
			break;
	}
}

void LLC::send_seq_number(uint8_t seq_number) {
	if (type() != LLC::INFORMATION)
		return;
	control_field.info.send_seq_num = seq_number;
}

void LLC::receive_seq_number(uint8_t seq_number) {
	switch (type()) {
		case LLC::UNNUMBERED:
			return;
		case LLC::INFORMATION:
			control_field.info.recv_seq_num = seq_number;
			break;
		case LLC::SUPERVISORY:
			control_field.super.recv_seq_num = seq_number;
			break;
	}
}

void LLC::poll_final(bool value) {
	switch (type()) {
		case LLC::UNNUMBERED:
			control_field.unnumbered.poll_final_bit = value;
			break;
		case LLC::INFORMATION:
			control_field.info.poll_final_bit = value;
			return;
		case LLC::SUPERVISORY:
			control_field.super.poll_final_bit = value;
			break;
	}

}

void LLC::supervisory_function(LLC::SupervisoryFunctions new_func) {
	if (type() != LLC::SUPERVISORY)
		return;
	control_field.super.supervisory_func = new_func;
}

void LLC::modifier_function(LLC::ModifierFunctions mod_func) {
	if (type() != LLC::UNNUMBERED)
		return;
	control_field.unnumbered.mod_func1 = mod_func >> 3;
	control_field.unnumbered.mod_func2 = mod_func & 0x07;
}

void LLC::add_xid_information(uint8_t xid_id, uint8_t llc_type_class, uint8_t receive_window) {
	uint8_t* XID = new uint8_t[3];
	XID[0] = 0;
	XID[0] = xid_id;
	XID[1] = 0;
	XID[1] = llc_type_class;
	XID[2] = 0;
	XID[2] = receive_window & 0x7F;

	information_field_length += 3;
	information_fields.push_back(std::pair<uint8_t, uint8_t*>(3, XID));

}

uint32_t LLC::header_size() const {
	return sizeof(_header) + control_field_length + information_field_length;
}

void LLC::clear_information_fields() {
	information_field_length = 0;
	information_fields.clear();
}

Tins::PDU *LLC::clone_pdu() const {
	LLC *new_pdu = new LLC();
	new_pdu->copy_fields(this);
	return new_pdu;
}

void LLC::copy_fields(const LLC *other) {
	std::memcpy(&_header, &other->_header, sizeof(_header));
	control_field_length = other->control_field_length;
	control_field = other->control_field;
	information_field_length = other->information_field_length;
	for (list<pair<uint8_t, uint8_t*> >::const_iterator it = other->information_fields.begin(); it != other->information_fields.end(); it++) {
		uint8_t* new_info_field = new uint8_t[it->first];
		std::memcpy(new_info_field, it->second, it->first);
		information_fields.push_back(pair<uint8_t, uint8_t*>(it->first, new_info_field));
	}
}

void LLC::write_serialization(uint8_t *buffer, uint32_t total_sz, const Tins::PDU *parent) {
	assert(total_sz >= header_size());
	std::memcpy(buffer, &_header, sizeof(_header));
	buffer += sizeof(_header);
	switch (type()) {
		case LLC::UNNUMBERED:
			std::memcpy(buffer, &(control_field.unnumbered), sizeof(un_control_field));
			buffer += sizeof(un_control_field);
			break;
		case LLC::INFORMATION:
			std::memcpy(buffer, &(control_field.info), sizeof(info_control_field));
			buffer += sizeof(info_control_field);
			break;
		case LLC::SUPERVISORY:
			std::memcpy(buffer, &(control_field.super), sizeof(super_control_field));
			buffer += sizeof(super_control_field);
			break;
	}

	for (list<pair<uint8_t, uint8_t*> >::iterator it = information_fields.begin(); it != information_fields.end(); it++) {
		std::memcpy(buffer, it->second, it->first);
		buffer += it->first;
	}
}

}
