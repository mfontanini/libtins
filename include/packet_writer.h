/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef TINS_PACKET_WRITER_H
#define TINS_PACKET_WRITER_H

#include <pcap.h>
#include <string>

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
    void write(PDU *pdu);
    
    /**
     * \brief Writes all the PDUs in the range [start, end)
     * \param start A forward iterator pointing to the first PDU
     * to be written.
     * \param end A forward iterator pointing to one past the last
     * PDU in the range.
     * \return ForwardIterator which will be a copy of end.
     */
    template<typename ForwardIterator>
    ForwardIterator write(ForwardIterator start, ForwardIterator end) {
        while(start != end) 
            write(*start++);
        return start;
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
