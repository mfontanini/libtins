/*
 * Copyright (c) 2012, Nasel
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

#include <algorithm>
#include "cxxstd.h"
#include "pdu.h"
#include "timestamp.h"

namespace Tins {
template<typename WrappedType, typename TimestampType>
class PacketWrapper;
    
typedef PacketWrapper<PDU&, const Timestamp&> RefPacket;
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
    const Timestamp &timestamp() const {
        return ts_;
    }
private:
    friend class BaseSniffer;
    
    PacketWrapper(pdu_type pdu, const Timestamp &ts) 
    : pdu_(pdu), ts_(ts) {}
    
    PacketWrapper(const PacketWrapper&);
    PacketWrapper& operator=(const PacketWrapper&);
    void* operator new (size_t size);
    void operator delete (void *p);

    pdu_type pdu_;
    timestamp_type ts_;
};

/**
 * \brief Represents a sniffed packet.
 * 
 * A Packet contains a PDU pointer and a Timestamp object. Packets
 * <b>will delete</b> the stored PDU* unless you call release_pdu at 
 * some point before destruction. 
 */
class Packet {
public:
    /**
     * \brief Default constructs a Packet.
     * 
     * The PDU* will be set to a null pointer.
     */
    Packet() 
    : pdu_(0) { }
    
    /**
     * \brief Constructs a Packet from a RefPacket.
     * 
     * This calls PDU::clone on the RefPacket's PDU.
     * 
     */
    Packet(const RefPacket &pck) 
    : pdu_(pck.pdu().clone()), ts(pck.timestamp()) { }

    /**
     * \brief Constructs a Packet from a PtrPacket object.
     */
    Packet(const PtrPacket &pck)
    : pdu_(pck.pdu()), ts(pck.timestamp()) { }
    
    /**
     * \brief Copy constructor.
     * 
     * This calls PDU::clone on the rhs's PDU* member.
     */
    Packet(const Packet &rhs) : ts(rhs.timestamp()) {
        pdu_ = rhs.pdu() ? rhs.pdu()->clone() : 0;
    }
    
    /**
     * \brief Copy assignment operator.
     * 
     * This calls PDU::clone on the rhs's PDU* member.
     */
    Packet& operator=(const Packet &rhs) {
        if(this != &rhs) {
            delete pdu_;
            ts = rhs.timestamp();
            pdu_ = rhs.pdu() ? rhs.pdu()->clone() : 0;
        }
        return *this;
    }
    
    #if TINS_IS_CXX11
    /**
     * Move constructor.
     */
    Packet(Packet &&rhs) : pdu_(rhs.pdu()), ts(rhs.timestamp()) {
        rhs.pdu_ = nullptr;
    }
    
    /**
     * Move assignment operator.
     */
    Packet& operator=(Packet &&rhs) { 
        if(this != &rhs) {
            std::swap(pdu_, rhs.pdu_);
            ts = rhs.timestamp();
        }
        return *this;
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
    const Timestamp &timestamp() const {
        return ts;
    }
    
    /**
     * \brief Returns the stored PDU*. 
     * 
     * Caller <b>must not</b> delete the pointer. \sa Packet::release_pdu
     */
    PDU *pdu() {
        return pdu_;
    }
    
    /**
     * \brief Returns the stored PDU*. 
     * 
     * Caller <b>must not</b> delete the pointer. \sa Packet::release_pdu
     */
    const PDU *pdu() const {
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
    PDU *release_pdu() {
        PDU *some_pdu = pdu_;
        pdu_ = 0;
        return some_pdu;
    }
    
    /**
     * \brief Tests whether this is Packet contains a valid PDU.
     * 
     * \return true if pdu() == nullptr, false otherwise.
     */
    operator bool() const {
        return pdu_;
    }
private:
    PDU *pdu_;
    Timestamp ts;
};
}

#endif // TINS_PACKET_H
