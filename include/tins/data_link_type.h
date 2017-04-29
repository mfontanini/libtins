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

#ifndef TINS_DATA_LINK_TYPE_H
#define TINS_DATA_LINK_TYPE_H

#include <pcap.h>

namespace Tins {

class EthernetII;
class RadioTap;
class Dot11;
class Dot3;
class SLL;
class Loopback;
class PPI;

/**
 * \struct DataLinkType
 * \brief Maps a libtins link layer PDU to a libpcap data link identifier.
 *
 * This is an empty class that should be instantiated with any object that 
 * represents a link layer PDU (EthernetII, Dot11, RadioTap, etc):
 *
 * \code
 * // Instantiate it and pass it to PacketWriter's constructor.
 * PacketWriter writer("file.pcap", DataLinkType<RadioTap>());
 * \endcode
 */
template<typename T>
struct DataLinkType;

#define TINS_MAKE_DATA_LINK_TYPE(tins_type, pcap_type) \
template<> \
struct DataLinkType<tins_type> { \
    static const int type = pcap_type; \
    int get_type() const { \
        return type; \
    } \
}; 

TINS_MAKE_DATA_LINK_TYPE(EthernetII, DLT_EN10MB)
TINS_MAKE_DATA_LINK_TYPE(Dot3, DLT_EN10MB)
TINS_MAKE_DATA_LINK_TYPE(SLL, DLT_LINUX_SLL)
TINS_MAKE_DATA_LINK_TYPE(Loopback, DLT_LOOP)
TINS_MAKE_DATA_LINK_TYPE(PPI, DLT_PPI)
TINS_MAKE_DATA_LINK_TYPE(Dot11, DLT_IEEE802_11)
TINS_MAKE_DATA_LINK_TYPE(RadioTap, DLT_IEEE802_11_RADIO)

#undef TINS_MAKE_DATA_LINK_TYPE

} // Tins

#endif // TINS_DATA_LINK_TYPE_H
