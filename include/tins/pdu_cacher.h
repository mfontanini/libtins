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

#ifndef TINS_PDU_CACHER_H
#define TINS_PDU_CACHER_H

#include <cstring>
#include <tins/pdu.h>
#include <tins/macros.h>

namespace Tins {
/**
 * \class PDUCacher
 * \brief PDU wrapper that caches the result of the wrapped PDU's 
 * serialization.
 * 
 * This wrapper class holds a PDU of the template parameter type, and
 * forwards every PDU virtual call to the stored object. Whenever a
 * call to write_serialization is performed on this wrapper, the result
 * is cached in a PDU::serialization_type. On subsequent calls to
 * PDUCacher::write_serialization, the contents of that cache will be
 * written to the output buffer.
 * 
 * This class should provide a nice performance boost if you're sending
 * over and over a packet that requires some computation while being
 * serialized, such as performing checksums, iterate and copy options,
 * etc.
 */
template <typename T>
class PDUCacher : public PDU {
public:
    /**
     * The cached PDU type.
     */
    typedef T cached_type;
    
    /**
     * 
     */
    static const PDU::PDUType pdu_flag = cached_type::pdu_flag;
    
    /**
     * Default constructs the cached PDU.
     */
    PDUCacher() 
    : cached_size_() {}
    
    /**
     * Constructor from a cached_type.
     * \param pdu The PDU to be copy constructed.
     */
    PDUCacher(const cached_type& pdu) 
    : cached_(pdu), cached_size_()  {}
    
    /**
     * Forwards the call to the cached PDU. 
     * 
     * \sa PDU::header_size.
     */
    uint32_t header_size() const {
        if (cached_serialization_.empty()) {
            cached_size_ = cached_.size();
        }
        return cached_size_;
    }
    
    /**
     * Forwards the call to the cached PDU. 
     * 
     * \sa PDU::clone.
     */
    PDUCacher* clone() const {
        return new PDUCacher<T>(*this);
    }
    
    /**
     * Forwards the call to the cached PDU. 
     * 
     * \sa PDU::send.
     */
    void send(PacketSender& sender, const NetworkInterface& iface) {
        cached_.send(sender, iface);
    }
    
    /**
     * Forwards the call to the cached PDU. 
     * 
     * \sa PDU::recv_responde.
     */
    PDU* recv_response(PacketSender& sender, const NetworkInterface& iface) {
        return cached_.recv_response(sender, iface);
    }
    
    /**
     * Forwards the call to the cached PDU. 
     * 
     * \sa PDU::matches_response.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const {
        return cached_.matches_response(ptr, total_sz);
    }
    
    /**
     * Forwards the call to the cached PDU. 
     * 
     * \sa PDU::matches_flag.
     */
    bool matches_flag(PDUType flag) const {
        return cached_.matches_flag(flag);
    }
    
    /**
     * Forwards the call to the cached PDU. 
     * 
     * \sa PDU::pdu_type.
     */
    PDUType pdu_type() const {
        return cached_.pdu_type();
    }
private:
    void write_serialization(uint8_t* buffer, uint32_t total_sz) {
        if (cached_serialization_.size() != total_sz) {
            cached_serialization_ = cached_.serialize();
        }
        std::memcpy(buffer, &*cached_serialization_.begin(), cached_serialization_.size());
    }

    cached_type cached_;
    PDU::serialization_type cached_serialization_;
    mutable uint32_t cached_size_;
};
}

#endif // TINS_PDU_CACHER_H
