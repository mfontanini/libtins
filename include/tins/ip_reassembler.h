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

#ifndef TINS_IP_REASSEMBLER_H
#define TINS_IP_REASSEMBLER_H

#include <vector>
#include <list>
#include <map>
#include <tins/pdu.h>
#include <tins/macros.h>
#include <tins/ip_address.h>
#include <tins/ip.h>

namespace Tins {

/** 
 * \cond
 */
namespace Internals {
class IPv4Fragment {
public:
    typedef PDU::serialization_type payload_type;

    IPv4Fragment() : offset_() { }

    template<typename T>
    IPv4Fragment(T* pdu, uint16_t offset)
    : payload_(pdu->serialize()), offset_(offset) {
        
    }
    
    uint16_t trim(uint16_t amount);
    
    const payload_type& payload() const {
        return payload_;
    }
    
    size_t size() const {
        return payload_.size();
    }

    uint16_t offset() const {
        return offset_;
    }
private:
    payload_type payload_;
    uint16_t offset_;
};

class TINS_API IPv4Stream {
public:
    IPv4Stream();
    
    size_t add_fragment(IP* ip);
    bool is_complete() const;
    PDU* allocate_pdu() const;
    const IP& first_fragment() const;
    size_t size() const { return received_size_; }
private:
    typedef std::vector<IPv4Fragment> fragments_type;
    
    uint16_t extract_offset(const IP* ip);
    bool extract_more_frag(const IP* ip);

    fragments_type fragments_;
    size_t received_size_;
    size_t total_size_;
    IP first_fragment_;
    bool received_end_;
};
} // namespace Internals

/** 
 * \endcond
 */

/**
 * \brief Reassembles fragmented IP packets.
 *
 * This class is fairly simple: just feed packets into it using IPv4Reassembler::process.
 * If the return value is IPv4Reassembler::FRAGMENTED, then the packet is fragmented
 * and we haven't yet seen the missing fragments, hence we can't reassemble it.
 * If the function returns either IPv4Reassembler::NOT_FRAGMENTED (meaning the
 * packet wasn't fragmented) or IPv4Reassembler::REASSEMBLED (meaning the packet was
 * fragmented but it's now reassembled), then you can process the packet normally.
 *
 * Simple example:
 *
 * \code
 * IPv4Reassembler reassembler;
 * Sniffer sniffer = ...;
 * sniffer.sniff_loop([&](PDU& pdu) {
 *     // Process it in any case, unless it's fragmented (and can't be reassembled yet)
 *     if (reassembler.process(pdu) != IPv4Reassembler::FRAGMENTED) {
 *         // Now actually process the packet
 *         process_packet(pdu);
 *     }
 * });
 * \endcode 
 */
class TINS_API IPv4Reassembler {
public:
    /**
     * The status of each processed packet.
     */
    enum PacketStatus {
        NOT_FRAGMENTED, ///< The given packet is not fragmented
        FRAGMENTED, ///< The given packet is fragmented and can't be reassembled yet
        REASSEMBLED ///< The given packet was fragmented but is now reassembled
    };

    TINS_DEPRECATED(typedef PacketStatus packet_status);

    /**
     * The type used to represent the overlapped segment reassembly 
     * technique to be used.
     */
    enum OverlappingTechnique {
        NONE,
        BSD
    };

    /**
     * Default constructor
     */
    IPv4Reassembler();

    /**
     * Constructs an IPV4Reassembler.
     * 
     * \param technique The technique to be used for reassembling
     * overlapped fragments.
     */
    IPv4Reassembler(OverlappingTechnique technique);

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
    PacketStatus process(PDU& pdu);

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
    static const size_t MAX_BUFFERED_BYTES;
    static const size_t BUFFERED_BYTES_LOW_THRESHOLD;

    typedef std::pair<IPv4Address, IPv4Address> address_pair;
    typedef std::pair<uint16_t, address_pair> key_type;
    typedef std::pair<key_type, Internals::IPv4Stream*> key_stream_type;
    typedef std::list<key_stream_type> ordered_streams_type;
    typedef std::map<key_type, ordered_streams_type::iterator> streams_type;

    Internals::IPv4Stream& get_stream(key_type key);
    void remove_stream(key_type key);
    void prune_streams();
    key_type make_key(const IP* ip) const;
    address_pair make_address_pair(IPv4Address addr1, IPv4Address addr2) const;
    
    streams_type streams_;
    ordered_streams_type ordered_streams_;
    OverlappingTechnique technique_;
    size_t buffered_bytes_;
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
    : functor_(func) {

    }

    /**
     * \brief Tries to reassemble the packet and forwards it to 
     * the functor.
     * 
     * \param pdu The packet to process
     * \return true if the packet wasn't forwarded, otherwise
     * the value returned by the functor.
     */
    bool operator()(PDU& pdu) {
        // Forward it unless it's fragmented.
        if (reassembler_.process(pdu) != IPv4Reassembler::FRAGMENTED) {
            return functor_(pdu);
        }
        else {
            return true;
        }
    }
private:
    IPv4Reassembler reassembler_;
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

} // Tins

#endif // TINS_IP_REASSEMBLER_H
