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

#ifndef TINS_PACKET_WRITER_H
#define TINS_PACKET_WRITER_H

#include "utils.h"
#include <string>
#include <iterator>
#include <pcap.h>
#include "data_link_type.h"
#include "macros.h"
#include "cxxstd.h"

struct timeval;

namespace Tins {
class PDU;
class Packet;

/**
 * \class PacketWriter
 * \brief Writes PDUs to a pcap format file.
 *
 * This class can be used to write packets into a <i>pcap</i> format
 * file. It supports both writing packets one by one, or writing all
 * packets in a range (provided by iterators), so you can use it
 * to dump all packets in a vector.
 *
 * Since you might use both PDU objects and pointers to them,
 * both the PacketWriter::write overload that takes a single object
 * or the one that takes an iterator range accept a PDU reference type
 * as well as any type that can be dereferenced until a PDU type is found.
 * This means you can use both raw and smart pointers. 
 *
 * For example:
 *
 * \code
 * // Differents types holding PDUs
 * EthernetII object;
 * std::shared_ptr<PDU> smart_ptr = ...;
 * std::vector<std::shared_ptr<PDU>> vt = ....;
 *
 * // The writer we'll use
 * PacketWriter writer("/tmp/file.pcap", DataLinkType<EthernetII>());
 *
 * // Now write all of them
 * writer.write(object);
 * writer.write(smart_ptr);
 * writer.write(vt.begin(), vt.end());
 * \endcode
 */
class TINS_API PacketWriter {
public:
    /**
     * \brief The type of PDUs that will be written to this file (deprecated).
     * \deprecated Use DataLinkType instead of this enum.
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
     *
     * This method takes a DataLinkType, which indicates the link
     * layer protocol that will be used on the packets to write.
     *
     * For example, you can write packets that contain an 
     * EthernetII link layer type by doing:
     * 
     * \code
     * // Construct a PacketWriter
     * PacketWriter writer("/tmp/test.pcap", DataLinkType<EthernetII>());
     * // Write some packet
     * writer.write(packet);
     * \endcode
     * 
     * \param file_name The file in which to store the written PDUs.
     * \param lt A DataLinkType that represents the link layer
     * protocol to use.
     * \sa PcapIdentifier.
     */
    template<typename T>
    PacketWriter(const std::string& file_name, const DataLinkType<T>& lt) {
        init(file_name, lt.get_type());
    }

    /**
     * \brief Constructs a PacketWriter.
     * 
     * \deprecated Use the PacketWriter(const std::string&, const DataLinkType<T>&)
     * constructor.
     * 
     * \param file_name The file in which to store the written PDUs.
     * \param lt The link type which will be written to this file.
     * \sa LinkType.
     */
    PacketWriter(const std::string& file_name, LinkType lt);
    
    #if TINS_IS_CXX11
        /**
         * \brief Move constructor.
         * 
         * Note that calling PacketWriter::write on an previously moved
         * object will lead to undefined behaviour.
         * 
         * \param rhs The PacketWriter to be moved.
         */
        PacketWriter(PacketWriter &&rhs) TINS_NOEXCEPT {
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
        PacketWriter& operator=(PacketWriter &&rhs) TINS_NOEXCEPT {
            handle_ = 0;
            dumper_ = 0;
            std::swap(handle_, rhs.handle_);
            std::swap(dumper_, rhs.dumper_);
            return* this;
        }
    #endif
    
    /**
     * \brief Destructor.
     *
     * Gracefully closes the output file.
     */
    ~PacketWriter();
    
    /**
     * \brief Writes a PDU to this file. 
     * \param pdu The PDU to be written.
     */
    void write(PDU& pdu);

    /**
     * \brief Writes a Packet to this file. 
     *
     * The timestamp used on the entry for this packet will be the Timestamp
     * object associated with this packet.
     *
     * \param packet The packet to be written.
     */
    void write(Packet& packet);
    
    /**
     * \brief Writes a PDU to this file. 
     * 
     * The template parameter T must at some point yield a PDU& after
     * applying operator* one or more than one time. This accepts both
     * raw and smart pointers.
     */
    template<typename T>
    void write(T& pdu) {
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
        while (start != end) {
            write(Utils::dereference_until_pdu(*start++));
        }
    }
private:
    // You shall not copy
    PacketWriter(const PacketWriter&);
    PacketWriter& operator=(const PacketWriter&);

    void init(const std::string& file_name, int link_type);
    void write(PDU& pdu, const struct timeval& tv);

    pcap_t* handle_;
    pcap_dumper_t* dumper_; 
};
}

#endif // TINS_PACKET_WRITER_H
