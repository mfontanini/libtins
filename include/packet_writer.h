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

#ifndef TINS_PACKET_WRITER_H
#define TINS_PACKET_WRITER_H

#include <string>
#include <iterator>
#include <pcap.h>

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
        ETH2 = DLT_EN10MB
    };
    
    /**
     * \brief Constructs a PacketWriter.
     * \param file_name The file in which to store the written PDUs.
     * \param lt The link type which will be written to this file.
     * \sa LinkType.
     */
    PacketWriter(const std::string &file_name, LinkType lt);
    
    /**
     * Destructor.
     */
    ~PacketWriter();
    
    /**
     * \brief Writes a PDU to this file. 
     */
    void write(PDU &pdu);
    
    /**
     * \brief Writes all the PDUs in the range [start, end)
     * \param start A forward iterator pointing to the first PDU
     * to be written.
     * \param end A forward iterator pointing to one past the last
     * PDU in the range.
     */
    template<typename ForwardIterator>
    void write(ForwardIterator start, ForwardIterator end) {
        typedef typename std::iterator_traits<ForwardIterator>::value_type value_type;
        typedef derefer<value_type> deref_type;
        
        while(start != end) 
            write(deref_type::deref(*start++));
    }
private:
    template<typename T>
    struct derefer {
        static T &deref(T &value) {
            return value;
        }
    };
    
    template<typename T>
    struct derefer<T*> {
        static T &deref(T *value) {
            return *value;
        }
    };

    // You shall not copy
    PacketWriter(const PacketWriter&);
    PacketWriter& operator=(const PacketWriter&);

    pcap_t *handle;
    pcap_dumper_t *dumper; 
};
}

#endif // TINS_PACKET_WRITER_H
