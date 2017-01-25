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

#include <stdexcept>
#include <cstring>
#include "llc.h"
#include "stp.h"
#include "rawpdu.h"
#include "exceptions.h"
#include "memory_helpers.h"

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

const uint8_t LLC::GLOBAL_DSAP_ADDR = 0xFF;
const uint8_t LLC::NULL_ADDR = 0x00;

LLC::LLC()
: header_(), control_field(), type_(LLC::INFORMATION) {
	control_field_length_ = 2;
	information_field_length_ = 0;
}

LLC::LLC(uint8_t dsap, uint8_t ssap) 
: control_field(), type_(LLC::INFORMATION) {
	header_.dsap = dsap;
	header_.ssap = ssap;
	control_field_length_ = 2;
	information_field_length_ = 0;
}

LLC::LLC(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    if (!stream) {
        throw malformed_packet();
    }
	information_field_length_ = 0;
	if ((*stream.pointer() & 0x03) == LLC::UNNUMBERED) {
		type(LLC::UNNUMBERED);
        stream.read(control_field.unnumbered);
		// TODO: Create information fields if corresponding.
	}
	else {
		type((Format)(*stream.pointer() & 0x03));
		control_field_length_ = 2;
		stream.read(control_field.info);
	}
    if (stream) {
        if (dsap() == 0x42 && ssap() == 0x42) {
            inner_pdu(new Tins::STP(stream.pointer(), stream.size()));
        }
        else {
            inner_pdu(new Tins::RawPDU(stream.pointer(), stream.size()));
        }
    }
}

void LLC::group(bool value) {
	if (value) {
		header_.dsap |= 0x01;
	}
	else {
		header_.dsap &= 0xFE;
	}
}

void LLC::dsap(uint8_t new_dsap) {
	header_.dsap = new_dsap;
}

void LLC::response(bool value) {
	if (value) {
		header_.ssap |= 0x01;
	}
	else {
		header_.ssap &= 0xFE;
	}
}

void LLC::ssap(uint8_t new_ssap) {
	header_.ssap = new_ssap;
}

void LLC::type(LLC::Format type) {
	type_ = type;
	switch (type) {
		case LLC::INFORMATION:
			control_field_length_ = 2;
			control_field.info.type_bit = 0;
			break;
		case LLC::SUPERVISORY:
			control_field_length_ = 2;
			control_field.super.type_bit = 1;
			break;
		case LLC::UNNUMBERED:
			control_field_length_ = 1;
			control_field.unnumbered.type_bits = 3;
			break;
	}
}

void LLC::send_seq_number(uint8_t seq_number) {
	if (type() != LLC::INFORMATION) {
		return;
    }
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
	if (type() != LLC::SUPERVISORY) {
		return;
    }
	control_field.super.supervisory_func = new_func;
}

void LLC::modifier_function(LLC::ModifierFunctions mod_func) {
	if (type() != LLC::UNNUMBERED) {
		return;
    }
	control_field.unnumbered.mod_func1 = mod_func >> 3;
	control_field.unnumbered.mod_func2 = mod_func & 0x07;
}

void LLC::add_xid_information(uint8_t xid_id, uint8_t llc_type_class, uint8_t receive_window) {
    field_type xid(3);
    xid[0] = xid_id;
    xid[1] = llc_type_class;
    xid[2] = receive_window;
	information_field_length_ += static_cast<uint8_t>(xid.size());
    information_fields_.push_back(xid);
}

uint32_t LLC::header_size() const {
	return sizeof(header_) + control_field_length_ + information_field_length_;
}

void LLC::clear_information_fields() {
	information_field_length_ = 0;
	information_fields_.clear();
}

void LLC::write_serialization(uint8_t* buffer, uint32_t total_sz, const Tins::PDU* /*parent*/) {
    OutputMemoryStream stream(buffer, total_sz);
    if (inner_pdu() && inner_pdu()->pdu_type() == PDU::STP) {
        dsap(0x42);
        ssap(0x42);
    }
    stream.write(header_);
	switch (type()) {
		case LLC::UNNUMBERED:
            stream.write(control_field.unnumbered);
			break;
		case LLC::INFORMATION:
            stream.write(control_field.info);
			break;
		case LLC::SUPERVISORY:
            stream.write(control_field.super);
			break;
	}

	for (field_list::const_iterator it = information_fields_.begin(); it != information_fields_.end(); ++it) {
        stream.write(it->begin(), it->end());
	}
}

} // Tins
