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

#ifndef TINS_CHECKSUM_UTILS_H
#define TINS_CHECKSUM_UTILS_H

#include <stdint.h>
#include <tins/macros.h>

namespace Tins {

class IPv4Address;
class IPv6Address;

namespace Utils {

/** 
 * \brief Does the 16 bits sum of all 2 bytes elements between start and end.
 *
 * This is the checksum used by IP, UDP and TCP. If there's and odd number of
 * bytes, the last one is padded and added to the checksum. 
 * \param start The pointer to the start of the buffer.
 * \param end The pointer to the end of the buffer(excluding the last element).
 * \return Returns the checksum between start and end (non inclusive) 
 * in network endian
 */
TINS_API uint32_t do_checksum(const uint8_t* start, const uint8_t* end);

/** 
 * \brief Computes the 16 bit sum of the input buffer.
 *
 * If there's and odd number of bytes in the buffer, the last one is padded and 
 * added to the checksum. 
 * \param start The pointer to the start of the buffer.
 * \param end The pointer to the end of the buffer(excluding the last element).
 * \return Returns the checksum between start and end (non inclusive) 
 * in network endian
 */
TINS_API uint16_t sum_range(const uint8_t* start, const uint8_t* end);

/**
 * \brief Performs the pseudo header checksum used in TCP and UDP PDUs.
 *
 * \param source_ip The source ip address.
 * \param dest_ip The destination ip address.
 * \param len The length to be included in the pseudo header.
 * \param flag The flag to use in the protocol field of the pseudo header.
 * \return The pseudo header checksum.
 */
TINS_API uint32_t pseudoheader_checksum(IPv4Address source_ip,
                                        IPv4Address dest_ip,
                                        uint16_t len,
                                        uint16_t flag);

/**
 * \brief Performs the pseudo header checksum used in TCP and UDP PDUs.
 *
 * \param source_ip The source ip address.
 * \param dest_ip The destination ip address.
 * \param len The length to be included in the pseudo header.
 * \param flag The flag to use in the protocol field of the pseudo header.
 * \return The pseudo header checksum.
 */
TINS_API uint32_t pseudoheader_checksum(IPv6Address source_ip,  
                                        IPv6Address dest_ip,
                                        uint16_t len,
                                        uint16_t flag);

/**
 * \brief Returns the 32 bit crc of the given buffer.
 *
 * \param data The input buffer.
 * \param data_size The size of the input buffer.
 */
TINS_API uint32_t crc32(const uint8_t* data, uint32_t data_size);

} // Utils
} // Tins

#endif // TINS_CHECKSUM_UTILS_H
