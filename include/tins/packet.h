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

#ifndef TINS_PACKET_H
#define TINS_PACKET_H

#include <tins/cxxstd.h>
#include <tins/pdu.h>
#include <tins/timestamp.h>

/**
 * \namespace Tins
 */
namespace Tins {

template<typename WrappedType, typename TimestampType>
class PacketWrapper;


/**
 * \brief Thin wrapper over a PDU and Timestamp reference.
 */
typedef PacketWrapper<PDU&, const Timestamp&> RefPacket;

/**
 * \brief Thin wrapper over a PDU pointer and a Timestamp.
 */
typedef PacketWrapper<PDU*, Timestamp> PtrPacket;

/**
 * \brief Represents a sniffed packet.
 * 
 * RefPackets contain a PDU reference and a timestamp. The difference between
 * this class and the Packet class is that this one contains a reference
 * to a PDU, and not a pointer to one. 
 * 
 * This class is only used in some BaseSniffer methods as a thin wrapper 
 * to a PDU pointer/reference. Only BaseSniffer and derived objects can
 * create instances of it.
 */
template<typename PDUType, typename TimestampType>
class PacketWrapper {
public:
    typedef PDUType pdu_type;
    typedef TimestampType timestamp_type;
    
    /**
     * \brief User defined conversion to wrapped_type.
     * 
     * This conversion is defined so that BaseSniffer::sniff_loop callback 
     * or code that calls BaseSniffer::next_packet can still receive a 
     * PDU pointer/reference without modifying the code at all.
     */
    operator pdu_type() {
        return pdu_;
    }
    
    /**
     * \brief Returns the wrapped_type.
     */
    pdu_type pdu() {
        return pdu_;
    }
    
    /**
     * \brief Returns the PDU const reference.
     */
    const pdu_type pdu() const {
        return pdu_;
    }
    
    /**
     * \brief Returns the packet timestamp.
     * 
     * This is the timestamp in which the packet was taken out of the
     * network interface/pcap file.
     */
    const Timestamp& timestamp() const {
        return ts_;
    }
private:
    friend class BaseSniffer;
    friend class SnifferIterator;
    
    PacketWrapper(pdu_type pdu, const Timestamp& ts) 
    : pdu_(pdu), ts_(ts) {}
    
    PacketWrapper(const PacketWrapper&);
    PacketWrapper& operator=(const PacketWrapper&);
    void* operator new (size_t size);
    void operator delete (void* p);

    pdu_type pdu_;
    timestamp_type ts_;
};

/**
 * \class Represents a sniffed packet.
 * 
 * A Packet contains a PDU pointer and a Timestamp object. Packets
 * <b>will delete</b> the stored PDU* unless you call release_pdu at 
 * some point before destruction. 
 */
class Packet {
public:
    /**
     * Tag used to specify that a Packet should own a PDU pointer.
     */
    struct own_pdu {

    };

    /**
     * \brief Default constructs a Packet.
     * 
     * The PDU* will be set to a null pointer.
     */
    Packet() 
    : pdu_(0) { }
    
    /**
     * \brief Constructs a Packet from a PDU* and a Timestamp.
     * 
     * The PDU is cloned using PDU::clone.
     */
    Packet(const PDU* apdu, const Timestamp& tstamp) 
    : pdu_(apdu->clone()), ts_(tstamp) { }

    /**
     * \brief Constructs a Packet from a PDU& and a Timestamp.
     * 
     * The PDU is cloned using PDU::clone.
     */
    Packet(const PDU& apdu, const Timestamp& tstamp) 
    : pdu_(apdu.clone()), ts_(tstamp) { }

    /**
     * \brief Constructs a Packet from a PDU* and a Timestamp.
     * 
     * The PDU* will be owned by the Packet. This means you
     * <b>do not</b> have to explicitly delete the pointer, that
     * will be done automatically by the Packet when it goes out
     * of scope.
     */
    Packet(PDU* apdu, const Timestamp& tstamp, own_pdu) 
    : pdu_(apdu), ts_(tstamp) { }
    
    /**
     * \brief Constructs a Packet from a const PDU&.
     * 
     * The timestamp will be set to the current time.
     * 
     * This calls PDU::clone on the PDU parameter.
     * 
     */
    Packet(const PDU& rhs) 
    : pdu_(rhs.clone()), ts_(Timestamp::current_time()) { }
    
    /**
     * \brief Constructs a Packet from a RefPacket.
     * 
     * This calls PDU::clone on the RefPacket's PDU.
     * 
     */
    Packet(const RefPacket& pck) 
    : pdu_(pck.pdu().clone()), ts_(pck.timestamp()) { }

    /**
     * \brief Constructs a Packet from a PtrPacket object.
     */
    Packet(const PtrPacket& pck)
    : pdu_(pck.pdu()), ts_(pck.timestamp()) { }
    
    /**
     * \brief Copy constructor.
     * 
     * This calls PDU::clone on the rhs's PDU* member.
     */
    Packet(const Packet& rhs) : ts_(rhs.timestamp()) {
        pdu_ = rhs.pdu() ? rhs.pdu()->clone() : 0;
    }
    
    /**
     * \brief Copy assignment operator.
     * 
     * This calls PDU::clone on the rhs's PDU* member.
     */
    Packet& operator=(const Packet& rhs) {
        if (this != &rhs) {
            delete pdu_;
            ts_ = rhs.timestamp();
            pdu_ = rhs.pdu() ? rhs.pdu()->clone() : 0;
        }
        return* this;
    }
    
    #if TINS_IS_CXX11
    /**
     * Move constructor.
     */
    Packet(Packet &&rhs) TINS_NOEXCEPT : pdu_(rhs.pdu()), ts_(rhs.timestamp()) {
        rhs.pdu_ = nullptr;
    }
    
    /**
     * Move assignment operator.
     */
    Packet& operator=(Packet &&rhs) TINS_NOEXCEPT { 
        if (this != &rhs) {
            PDU* tmp = std::move(pdu_);
            pdu_ = std::move(rhs.pdu_);
            rhs.pdu_ = std::move(tmp);
            ts_ = rhs.timestamp();
        }
        return* this;
    }
    #endif
    
    /**
     * \brief Packet destructor.
     * 
     * This calls operator delete on the stored PDU*.
     */
    ~Packet() {
        delete pdu_;
    }
    
    /**
     * Returns this Packet's timestamp.
     */
    const Timestamp& timestamp() const {
        return ts_;
    }
    
    /**
     * \brief Returns the stored PDU*. 
     * 
     * Caller <b>must not</b> delete the pointer. \sa Packet::release_pdu
     */
    PDU* pdu() {
        return pdu_;
    }
    
    /**
     * \brief Returns the stored PDU*. 
     * 
     * Caller <b>must not</b> delete the pointer. \sa Packet::release_pdu
     */
    const PDU* pdu() const {
        return pdu_;
    }
    
    /**
     * \brief Releases ownership of the stored PDU*.
     * 
     * This method returns the stored PDU* and sets the stored PDU* to
     * a null pointer, so the destructor will be well behaved. Use this
     * method if you want to keep the internal PDU* somewhere. Otherwise,
     * when Packet's destructor is called, the stored pointer will be 
     * deleted.
     */
    PDU* release_pdu() {
        PDU* some_pdu = pdu_;
        pdu_ = 0;
        return some_pdu;
    }
    
    /**
     * \brief Tests whether this is Packet contains a valid PDU.
     * 
     * \return true if pdu() == nullptr, false otherwise.
     */
    operator bool() const {
        return pdu_ ? true : false;
    }
    
    /**
     * 
     * \brief Concatenation operator.
     * 
     * Adds the PDU at the end of the PDU stack. 
     * 
     * \param rhs The PDU to be appended.
     */
    Packet& operator/=(const PDU& rhs) {
        pdu_ /= rhs;
        return* this;
    }
private:
    PDU* pdu_;
    Timestamp ts_;
};
}

#endif // TINS_PACKET_H
