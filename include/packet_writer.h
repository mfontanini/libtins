/*
 * Copyright (c) 2012, Matias Fontanini
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

#ifndef TINS_PACKET_WRITER_H
#define TINS_PACKET_WRITER_H

#include <string>
#include <iterator>
#include <pcap.h>
#include "utils.h"
#include "cxxstd.h"

namespace Tins {
class PDU;

/**
 * \class PacketWriter
 * \brief Writes PDUs to a pcap format file.
 */
class PacketWriter {
public:
    /**
     * \brief The type of PDUs that will be written to this file.
     * 
     * This flag should match the type of the lowest layer PDU to be
     * written.
     */
    enum LinkType {
        RADIOTAP = DLT_IEEE802_11_RADIO,
        DOT11 = DLT_IEEE802_11,
        ETH2 = DLT_EN10MB,
        DOT3 = DLT_EN10MB,
        SLL = DLT_LINUX_SLL
    };
    
    /**
     * \brief Constructs a PacketWriter.
     * \param file_name The file in which to store the written PDUs.
     * \param lt The link type which will be written to this file.
     * \sa LinkType.
     */
    PacketWriter(const std::string &file_name, LinkType lt);
    
    #if TINS_IS_CXX11
        /**
         * \brief Move constructor.
         * 
         * Note that calling PacketWriter::write on an previously moved
         * object will lead to undefined behaviour.
         * 
         * \param rhs The PacketWriter to be moved.
         */
        PacketWriter(PacketWriter &&rhs) noexcept {
            *this = std::move(rhs);
        }
        
        /**
         * \brief Move assignment operator.
         * 
         * Note that calling PacketWriter::write on an previously moved
         * object will lead to undefined behaviour.
         * 
         * \param rhs The PacketWriter to be moved.
         */
        PacketWriter& operator=(PacketWriter &&rhs) noexcept {
            handle = 0;
            dumper = 0;
            std::swap(handle, rhs.handle);
            std::swap(dumper, rhs.dumper);
            return *this;
        }
    #endif
    
    /**
     * Destructor.
     */
    ~PacketWriter();
    
    /**
     * \brief Writes a PDU to this file. 
     */
    void write(PDU &pdu);
    
    /**
     * \brief Writes a PDU to this file. 
     * 
     * The template parameter T must at some point yield a PDU& after
     * applying operator* one or more than one time. This accepts both
     * raw and smart pointers.
     */
    template<typename T>
    void write(T &pdu) {
        write(Utils::dereference_until_pdu(pdu));
    }
    
    /**
     * \brief Writes all the PDUs in the range [start, end)
     * \param start A forward iterator pointing to the first PDU
     * to be written.
     * \param end A forward iterator pointing to one past the last
     * PDU in the range.
     */
    template<typename ForwardIterator>
    void write(ForwardIterator start, ForwardIterator end) {
        while(start != end) 
            write(Utils::dereference_until_pdu(*start++));
    }
private:
    // You shall not copy
    PacketWriter(const PacketWriter&);
    PacketWriter& operator=(const PacketWriter&);

    pcap_t *handle;
    pcap_dumper_t *dumper; 
};
}

#endif // TINS_PACKET_WRITER_H
