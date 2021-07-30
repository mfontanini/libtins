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

#include <tins/pdu_iterator.h>
#include <tins/pdu.h>
#include <tins/packet.h>

namespace Tins {

// PDUIterator
PDUIterator::PDUIterator(pointer pdu)
: pdu_(pdu) {

}

PDUIterator::pointer PDUIterator::operator->() {
    return pdu_;
}

PDUIterator::pointer PDUIterator::operator->() const {
    return pdu_;
}

PDUIterator::value_type PDUIterator::operator*() {
    return *pdu_;
}

const PDU& PDUIterator::operator*() const {
    return *pdu_;
}

// ConstPDUIterator

ConstPDUIterator::ConstPDUIterator(pointer pdu)
: pdu_(pdu) {

}

ConstPDUIterator::ConstPDUIterator(PDUIterator iterator) 
: pdu_(&*iterator) {

}

ConstPDUIterator::pointer ConstPDUIterator::operator->() const {
    return pdu_;
}

ConstPDUIterator::value_type ConstPDUIterator::operator*() const {
    return *pdu_;
}

// Helpers

PDUIteratorRange<PDUIterator> iterate_pdus(PDU* pdu) {
    return PDUIteratorRange<PDUIterator>(pdu, nullptr);
}

PDUIteratorRange<PDUIterator> iterate_pdus(PDU& pdu) {
    return PDUIteratorRange<PDUIterator>(&pdu, nullptr);
}

PDUIteratorRange<PDUIterator> iterate_pdus(Packet& packet) {
    return PDUIteratorRange<PDUIterator>(packet.pdu(), nullptr);
}

PDUIteratorRange<ConstPDUIterator> iterate_pdus(const PDU* pdu) {
    return PDUIteratorRange<ConstPDUIterator>(pdu, nullptr);
}

PDUIteratorRange<ConstPDUIterator> iterate_pdus(const PDU& pdu) {
    return PDUIteratorRange<ConstPDUIterator>(&pdu, nullptr);
}

PDUIteratorRange<ConstPDUIterator> iterate_pdus(const Packet& packet) {
    return PDUIteratorRange<ConstPDUIterator>(packet.pdu(), nullptr);
}

} // Tins
