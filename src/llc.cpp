/*
 * Copyright (c) 2014, Matias Fontanini
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

#include <stdexcept>
#include <cstring>
#ifdef TINS_DEBUG
#include <cassert>
#endif
#include "llc.h"
#include "stp.h"
#include "rawpdu.h"
#include "exceptions.h"

namespace Tins {
const uint8_t LLC::GLOBAL_DSAP_ADDR = 0xFF;
const uint8_t LLC::NULL_ADDR = 0x00;

LLC::LLC()
: _type(LLC::INFORMATION) 
{
	memset(&_header, 0, sizeof(llchdr));
	control_field_length = 2;
	memset(&control_field, 0, sizeof(control_field));
	information_field_length = 0;
}

LLC::LLC(uint8_t dsap, uint8_t ssap) 
: _type(LLC::INFORMATION) 
{
	_header.dsap = dsap;
	_header.ssap = ssap;
	control_field_length = 2;
	memset(&control_field, 0, sizeof(control_field));
	information_field_length = 0;
}

LLC::LLC(const uint8_t *buffer, uint32_t total_sz) {
    // header + 1 info byte
	if(total_sz < sizeof(_header) + 1)
		throw malformed_packet();
	std::memcpy(&_header, buffer, sizeof(_header));
	buffer += sizeof(_header);
	total_sz -= sizeof(_header);
	information_field_length = 0;
	if ((buffer[0] & 0x03) == LLC::UNNUMBERED) {
        if(total_sz < sizeof(un_control_field))
            throw malformed_packet();
		type(LLC::UNNUMBERED);
		std::memcpy(&control_field.unnumbered, buffer, sizeof(un_control_field));
		buffer += sizeof(un_control_field);
		total_sz -= sizeof(un_control_field);
		//TODO: Create information fields if corresponding.
	}
	else {
        if(total_sz < sizeof(info_control_field))
            throw malformed_packet();
		type((Format)(buffer[0] & 0x03));
		control_field_length = 2;
		std::memcpy(&control_field.info, buffer, sizeof(info_control_field));
		buffer += 2;
		total_sz -= 2;
	}
    if(total_sz > 0) {
        if(dsap() == 0x42 && ssap() == 0x42)
            inner_pdu(new Tins::STP(buffer, total_sz));
        else
            inner_pdu(new Tins::RawPDU(buffer, total_sz));
    }
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
    field_type xid(3);
    xid[0] = xid_id;
    xid[1] = llc_type_class;
    xid[2] = receive_window;
	information_field_length += xid.size();
    information_fields.push_back(xid);
}

uint32_t LLC::header_size() const {
	return sizeof(_header) + control_field_length + information_field_length;
}

void LLC::clear_information_fields() {
	information_field_length = 0;
	information_fields.clear();
}

void LLC::write_serialization(uint8_t *buffer, uint32_t total_sz, const Tins::PDU *parent) {
    #ifdef TINS_DEBUG
	assert(total_sz >= header_size());
    #endif
    if(inner_pdu() && inner_pdu()->pdu_type() == PDU::STP) {
        dsap(0x42);
        ssap(0x42);
    }
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

	for (std::list<field_type>::const_iterator it = information_fields.begin(); it != information_fields.end(); it++) {
        std::copy(it->begin(), it->end(), buffer);
		buffer += it->size();
	}
}

}
