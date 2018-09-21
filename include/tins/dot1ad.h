/*
 * Copyright (c) 2018, Matias Fontanini
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

#ifndef TINS_DOT1AD_H
#define TINS_DOT1AD_H

#include <tins/dot1q.h>

namespace Tins {

/**
 * \class Dot1Q
 * Represents an IEEE 802.1ad PDU.
 */
class TINS_API Dot1AD : public Dot1Q {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT1AD;

    /**
     * Default constructor
     */
    Dot1AD(small_uint<12> tag_id = 0, bool append_pad = true) : Dot1Q(tag_id, append_pad) {
      };

    /**
     * \brief Constructs a Dot1AD object from a buffer and adds all
     * identifiable PDUs found in the buffer as children of this
     * one.
     *
     * If the next PDU is not recognized, then a RawPDU is used.
     *
     * If there is not enough size for a Dot1AD header in the buffer,
     * a malformed_packet exception is thrown.
     *
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot1AD(const uint8_t* buffer, uint32_t total_sz) : Dot1Q(buffer, total_sz) {
    };

    /**
     * \sa PDU::clone
     */
    Dot1AD* clone() const {
        return new Dot1AD(*this);
    }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }
};
}

#endif // TINS_DOT1AD_H
