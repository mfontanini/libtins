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

#include <tins/config.h>

#if !defined(TINS_RADIOTAP_WRITER_H) && defined(TINS_HAVE_DOT11)

#define TINS_RADIOTAP_WRITER_H

#include <vector>
#include <stdint.h>
#include <tins/radiotap.h>

namespace Tins {
namespace Utils {

class RadioTapParser;

/**
 * \brief Writes RadioTap options into a buffer
 *
 * This class can write RadioTap options into a buffer, respecting the alignment
 * of each of them.
 *
 * Note that RadioTap options are ordered. Writing multiple of them in a non
 * ascending order will involve several memory moves around the buffer so it
 * will be less efficient.
 */
class RadioTapWriter {
public:
    /**
     * \brief Constructs a RadioTapWriter object
     * 
     * Note that a reference to the buffer will be kept and updated so it must
     * be kept in scope while writing options to it
     */
    RadioTapWriter(std::vector<uint8_t>& buffer);

    /**
     * \brief Writes an option, adding/removing padding as needed
     *
     * The function returns true iff the option was added successfully. This will
     * always be the case, unless an option having that type is already set.
     *
     * \param option The option to be written
     */
    void write_option(const RadioTap::option& option);
private:
    std::vector<uint8_t> build_padding_vector(const uint8_t* last_ptr, RadioTapParser& parser);
    void update_paddings(const std::vector<uint8_t>& paddings, uint32_t offset);

    std::vector<uint8_t>& buffer_;
};

} // Utils
} // Tins

#endif // TINS_RADIOTAP_WRITER_H
