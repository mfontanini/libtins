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

#ifndef TINS_PDU_ITERATOR_H
#define TINS_PDU_ITERATOR_H

#include <iterator>

namespace Tins {

class PDU;
class Packet;

/**
 * Base class for PDU iterators
 */
template <typename Concrete>
class PDUIteratorBase {
public:
    /**
     * Iterator's category
     */
    typedef std::bidirectional_iterator_tag iterator_category;

    /**
     * Iterator difference type
     */
    typedef std::ptrdiff_t difference_type;

    /**
     * Advances this iterator
     */
    Concrete& operator++() {
        advance();
        return static_cast<Concrete&>(*this);
    }

    /**
     * Advances this iterator
     */
    Concrete operator++(int) {
        Concrete output = static_cast<Concrete&>(*this);
        advance();
        return output;
    }

    /**
     * Moves this iterator back
     */
    Concrete& operator--() {
        retreat();
        return static_cast<Concrete&>(*this);
    }

    /**
     * Moves this iterator back
     */
    Concrete operator--(int) {
        Concrete output = static_cast<Concrete&>(*this);
        retreat();
        return output;
    }
private:
    void advance() {
        Concrete& self = static_cast<Concrete&>(*this);
        self = Concrete(self->inner_pdu());
    }

    void retreat() {
        Concrete& self = static_cast<Concrete&>(*this);
        self = Concrete(self->parent_pdu());
    }
};

/**
 * Compares iterators for equality
 *
 * \param lhs The left hand side iterator to be compared
 * \param rhs The right hand side iterator to be compared
 */
template <typename Concrete>
bool operator==(const PDUIteratorBase<Concrete>& lhs, const PDUIteratorBase<Concrete>& rhs) {
    const PDU* lhs_pdu = &*static_cast<const Concrete&>(lhs);
    const PDU* rhs_pdu = &*static_cast<const Concrete&>(rhs);
    return lhs_pdu == rhs_pdu;
}

/**
 * Compares iterators for equality
 *
 * \param lhs The left hand side iterator to be compared
 * \param rhs The right hand side iterator to be compared
 */
template <typename Concrete>
bool operator!=(const PDUIteratorBase<Concrete>& lhs, const PDUIteratorBase<Concrete>& rhs) {
    return !(lhs == rhs);
}

/**
 * Iterator class for PDUs
 */
class PDUIterator : public PDUIteratorBase<PDUIterator> {
public:
    /**
     * The used pointer type
     */
    typedef PDU* pointer;

    /**
     * The used reference type
     */
    typedef PDU& reference;

    /**
     * The used value type
     */
    typedef PDU& value_type;

    /**
     * Constructs an iterator using a PDU
     *
     * \param pdu The PDU to be used for iteration
     */
    PDUIterator(pointer pdu);

    /**
     * Get the stored PDU pointer
     */
    pointer operator->();

    /**
     * Get the stored PDU pointer
     */
    pointer operator->() const;

    /**
     * Dereference and get the stored PDU
     */
    PDU& operator*();

    /**
     * Dereference and get the stored PDU
     */
    const PDU& operator*() const;
private:
    pointer pdu_;
};

/**
 * Const iterator class for PDUs
 */
class ConstPDUIterator : public PDUIteratorBase<PDUIterator> {
public:
    /**
     * The used pointer type
     */
    typedef const PDU* pointer;

    /**
     * The used reference type
     */
    typedef const PDU& reference;

    /**
     * The used value type
     */
    typedef const PDU& value_type;

    /**
     * Constructs an iterator using a PDU
     *
     * \param pdu The PDU to be used for iteration
     */
    ConstPDUIterator(pointer pdu);

    /**
     * Construct from a PDU iterator
     */
    ConstPDUIterator(PDUIterator iterator);

    /**
     * Get the stored PDU pointer
     */
    pointer operator->() const;

    /**
     * Dereference and get the stored PDU
     */
    value_type operator*() const;
private:
    pointer pdu_;
};

/*
 * \brief PDU iterator class
 *
 * This class allows iterating all PDUs in a packet.
 *
 * Note that this keeps pointers to the original PDUs so you need to guarantee that they're
 * still in scope while you iterate them.
 */
template <typename Iterator>
class PDUIteratorRange {
public:
    /**
     * Constructs a PDU iterator range
     *
     * \param start The beginning of the range
     * \param end The end of the range
     */
    PDUIteratorRange(Iterator start, Iterator end)
    : start_(start), end_(end) {

    }

    template <typename OtherIterator>
    PDUIteratorRange(const PDUIteratorRange<OtherIterator>& other)
    : start_(&*other.begin()), end_(&*other.end()) {

    } 

    /*
     * Gets the beginning of the range
     */ 
    Iterator begin() {
        return start_;
    }

    /*
     * Gets the beginning of the range
     */ 
    Iterator begin() const {
        return start_;
    }

    /*
     * Gets the end of the range
     */ 
    Iterator end() {
        return end_;
    }

    /*
     * Gets the end of the range
     */ 
    Iterator end() const {
        return end_;
    }
private:
    Iterator start_;
    Iterator end_;
};

/**
 * Creates an iterator range out of a PDU
 */
PDUIteratorRange<PDUIterator> iterate_pdus(PDU* pdu);

/**
 * Creates an iterator range out of a PDU
 */
PDUIteratorRange<PDUIterator> iterate_pdus(PDU& pdu);

/**
 * Creates an iterator range out of a PDU
 */
PDUIteratorRange<PDUIterator> iterate_pdus(Packet& packet);

/**
 * Creates an iterator range out of a PDU
 */
PDUIteratorRange<ConstPDUIterator> iterate_pdus(const PDU* pdu);

/**
 * Creates an iterator range out of a PDU
 */
PDUIteratorRange<ConstPDUIterator> iterate_pdus(const PDU& pdu);

/**
 * Creates an iterator range out of a packet
 */
PDUIteratorRange<ConstPDUIterator> iterate_pdus(const Packet& packet);

} // Tins

#endif // TINS_PDU_ITERATOR_H
