/*
 * Copyright (c) 2014, Matias Fontanini
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

#ifndef TINS_IP_REASSEMBLER_H
#define TINS_IP_REASSEMBLER_H

#include <vector>
#include <map>
#include "pdu.h"
#include "ip_address.h"

namespace Tins {
/** 
 * \cond
 */
class IP;
namespace Internals {
class IPv4Fragment {
public:
    typedef PDU::serialization_type payload_type;

    IPv4Fragment() : offset_() { }

    template<typename T>
    IPv4Fragment(T *pdu, uint16_t offset)
    : payload_(pdu->serialize()), offset_(offset) 
    {
        
    }
    
    const payload_type &payload() const {
        return payload_;
    }
    
    uint16_t offset() const {
        return offset_;
    }
private:
    payload_type payload_;
    uint16_t offset_;
};

class IPv4Stream {
public:
    IPv4Stream();
    
    void add_fragment(IP *ip);
    bool is_complete() const;
    PDU *allocate_pdu() const;
private:
    typedef std::vector<IPv4Fragment> fragments_type;
    
    uint16_t extract_offset(const IP *ip);
    bool extract_more_frag(const IP *ip);

    fragments_type fragments;
    bool received_end;
    uint8_t transport_proto;
    size_t received_size, total_size;
};
} // namespace Internals

/** 
 * \endcond
 */

/**
 * \brief Reassembles fragmented IP packets.
 */
class IPv4Reassembler {
public:
    /**
     * The status of each processed packet.
     */
    enum packet_status {
        NOT_FRAGMENTED,
        FRAGMENTED,
        REASSEMBLED
    };

    /**
     * The type used to represent the overlapped segment 
     * reassembly technique to be used.
     */
    enum overlapping_technique {
        NONE
    };

    /**
     * Constructs an IPV4Reassembler.
     * \param technique The technique to be used for reassembling
     * overlapped fragments.
     */
    IPv4Reassembler(overlapping_technique technique = NONE);

    /**
     * \brief Processes a PDU and tries to reassemble it.
     *
     * This method tries to reassemble the provided packet. If
     * the packet is successfully reassembled using previously
     * processed packets, its contents will be modified so that
     * it contains the whole payload and not just a fragment.
     * 
     * \param pdu The PDU to process.
     * \return NOT_FRAGMENTED if the PDU does not contain an IP
     * layer or is not fragmented, FRAGMENTED if the packet is 
     * fragmented or REASSEMBLED if the packet was fragmented 
     * but has now been reassembled.
     */
    packet_status process(PDU &pdu);

    /**
     * Removes all of the packets and data stored.
     */
    void clear_streams();

    /**
     * \brief Removes all of the packets and data stored that 
     * belongs to IP headers whose identifier, source and destination
     * addresses are equal to the provided parameters.
     * 
     * \param id The idenfier to search.
     * \param addr1 The source address to search.
     * \param addr2 The destinatin address to search.
     * \sa IP::id
     */
    void remove_stream(uint16_t id, IPv4Address addr1, IPv4Address addr2);
private:
    typedef std::pair<IPv4Address, IPv4Address> address_pair;
    typedef std::pair<uint16_t, address_pair> key_type;
    typedef std::map<key_type, Internals::IPv4Stream> streams_type;

    key_type make_key(const IP *ip) const;
    address_pair make_address_pair(IPv4Address addr1, IPv4Address addr2) const;
    
    streams_type streams;
    overlapping_technique technique;
};

/**
 * Proxy functor class that reassembles PDUs.
 */
template<typename Functor>
class IPv4ReassemblerProxy {
public:
    /**
     * Constructs the proxy from a functor object.
     *
     * \param func The functor object.
     */
    IPv4ReassemblerProxy(Functor func)
    : functor_(func)
    {

    }

    /**
     * \brief Tries to reassemble the packet and forwards it to 
     * the functor.
     * 
     * \param pdu The packet to process
     * \return true if the packet wasn't forwarded, otherwise
     * the value returned by the functor.
     */
    bool operator()(PDU &pdu) {
        // Forward it unless it's fragmented.
        if(reassembler.process(pdu) != IPv4Reassembler::FRAGMENTED)
            return functor_(pdu);
        else
            return true;
    }
private:
    IPv4Reassembler reassembler;
    Functor functor_;
};

/**
 * Helper function that creates an IPv4ReassemblerProxy.
 *
 * \param func The functor object to use in the IPv4ReassemblerProxy.
 * \return An IPv4ReassemblerProxy.
 */
template<typename Functor>
IPv4ReassemblerProxy<Functor> make_ipv4_reassembler_proxy(Functor func) {
    return IPv4ReassemblerProxy<Functor>(func);
}
}


#endif // TINS_IP_REASSEMBLER_H
