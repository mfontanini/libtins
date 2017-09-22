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

#ifndef TINS_PDU_ALLOCATOR_H
#define TINS_PDU_ALLOCATOR_H

#include <map>
#include <tins/pdu.h>

namespace Tins {
/**
 * \cond
 */
class EthernetII;
class SNAP;
class Dot1Q;
class SLL;
class IP;
class IPv6;

namespace Internals {

template<typename PDUType>
PDU* default_allocator(const uint8_t* buffer, uint32_t size) {
    return new PDUType(buffer, size);
}

template<typename Tag>
class PDUAllocator {
public:
    typedef typename Tag::identifier_type id_type;
    typedef PDU *(*allocator_type)(const uint8_t *, uint32_t);

    template<typename PDUType>
    static void register_allocator(id_type identifier) {
        allocators[identifier] = &default_allocator<PDUType>;
        pdu_types[PDUType::pdu_flag] = identifier;
    }

    static PDU* allocate(id_type identifier, const uint8_t* buffer, uint32_t size) {
        typename allocators_type::const_iterator it = allocators.find(identifier);
        return (it == allocators.end()) ? 0 : (*it->second)(buffer, size);
    }

    static bool pdu_type_registered(PDU::PDUType type) {
        return pdu_types.count(type) != 0;
    }

    static id_type pdu_type_to_id(PDU::PDUType type) {
        typename pdu_map_types::const_iterator it = pdu_types.find(type);
        return it->second;
    }
private:
    typedef std::map<id_type, allocator_type> allocators_type;
    typedef std::map<PDU::PDUType, id_type> pdu_map_types;

    static allocators_type allocators;
    static pdu_map_types pdu_types;
};

template<typename Tag>
typename PDUAllocator<Tag>::allocators_type PDUAllocator<Tag>::allocators;

template<typename Tag>
typename PDUAllocator<Tag>::pdu_map_types PDUAllocator<Tag>::pdu_types;

template<typename IDType>
struct pdu_tag {
    typedef IDType identifier_type;
};

template<typename PDUType>
struct pdu_tag_mapper;

#define TINS_GENERATE_TAG_MAPPER(pdu, id_type) \
template<> \
struct pdu_tag_mapper<pdu> { \
    typedef pdu_tag<id_type> type; \
}; 

TINS_GENERATE_TAG_MAPPER(EthernetII, uint16_t)
TINS_GENERATE_TAG_MAPPER(SNAP, uint16_t)
TINS_GENERATE_TAG_MAPPER(SLL, uint16_t)
TINS_GENERATE_TAG_MAPPER(Dot1Q, uint16_t)
TINS_GENERATE_TAG_MAPPER(IP, uint8_t)
TINS_GENERATE_TAG_MAPPER(IPv6, uint8_t)

#undef TINS_GENERATE_TAG_MAPPER

template<typename PDUType>
PDU* allocate(typename pdu_tag_mapper<PDUType>::type::identifier_type id, 
              const uint8_t* buffer, 
              uint32_t size) {
    return PDUAllocator<typename pdu_tag_mapper<PDUType>::type>::allocate(id, buffer, size);
}

template<typename PDUType>
bool pdu_type_registered(PDU::PDUType type) {
    return PDUAllocator<typename pdu_tag_mapper<PDUType>::type>::pdu_type_registered(type);
}

template<typename PDUType>
typename pdu_tag_mapper<PDUType>::type::identifier_type pdu_type_to_id(PDU::PDUType type)  {
    return PDUAllocator<typename pdu_tag_mapper<PDUType>::type>::pdu_type_to_id(type);
}

} // Interals
/**
 * \endcond
 */

/**
 * \brief Defines inner PDU allocators.
 */
namespace Allocators {
/**
 * \brief Registers an allocator for the provided PDU type.
 *
 * Registering a certain allocator for a PDU type is useful for 
 * extending the library. Once an allocator is registered, it will
 * be taken into account while constructing a PDU from a buffer.
 * 
 * If PDU finds that it cannot define which is the protocol
 * that should be allocated based on its protocol identifier, it
 * will try using the registered allocators if any.
 *
 * \code
 * // Register the 0x666 identifer. Now if EthernetII finds a
 * // network layer identifier field whose value is 0x666, it will
 * // use SomePDUType as its inner PDU type.
 * Allocators::register_allocator<EthernetII, SomePDUType>(0x666);
 * \endcode
 *
 * Note that some PDU types are grouped together. For example, 
 * registering an allocator for EthernetII will make it work for 
 * the rest of the link layer protocols, sine they should all work 
 * the same way.
 */
template<typename PDUType, typename AllocatedType>
void register_allocator(typename Internals::pdu_tag_mapper<PDUType>::type::identifier_type id) {
    Internals::PDUAllocator<
        typename Internals::pdu_tag_mapper<PDUType>::type
    >::template register_allocator<AllocatedType>(id);
}

} // Allocators
} // Tins

#endif // TINS_PDU_ALLOCATOR_H
