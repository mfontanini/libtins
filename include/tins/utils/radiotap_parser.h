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

#if !defined(TINS_RADIOTAP_PARSER_H) && defined(TINS_HAVE_DOT11)
#define TINS_RADIOTAP_PARSER_H

#include <stdint.h>
#include <tins/macros.h>
#include <tins/radiotap.h>
#include <tins/pdu_option.h>

namespace Tins {
namespace Utils {

struct RadioTapFlags;

/**
 * \brief Allows parsing RadioTap options
 *
 * RadioTap is a somehow tricky protocol to be parsed, as it has ordered flags,
 * alignment between options, etc. This class allows parsing options in a RadioTap
 * header without much trouble.
 */
class RadioTapParser {
public:
    /**
     * Represents the RadioTap namespace currently being parsed
     */
    enum NamespaceType {
        RADIOTAP_NS,
        VENDOR_NS,
        UNKNOWN_NS
    };

    /**
     * Represents the size and alignment of each RadioTap field
     */
    struct FieldMetadata {
        uint32_t size;
        uint32_t alignment;
    };

    /**
     * Contains metadata for each data field in RadioTap
     */
    static const FieldMetadata RADIOTAP_METADATA[];

    /**
     * Represents the maximum bit we have information for
     */
    static const uint32_t MAX_RADIOTAP_FIELD;

    /**
     * \brief Constructs a RadioTap parser around a payload
     *
     * Note that the payload is not copied, hence it must be kept in 
     * scope while the parser is still being used.
     *
     * The buffer should contain an entire RadioTap header, with optionally
     * extra data at the end, which will be ignored.
     *
     * \param buffer The buffer to be parsed
     */
    RadioTapParser(const std::vector<uint8_t>& buffer);

    /**
     * Gets the current namespace being parsed
     */
    NamespaceType current_namespace() const;

    /**
     * \brief Gets a 0 index based namespace index.
     *
     * This index will be incremented every time a new namespace is found
     */
    uint32_t current_namespace_index() const;

    /**
     * Gets the current field being parsed
     */
    RadioTap::PresentFlags current_field() const;

    /**
     * Gets the option the parsed is currently pointing at
     */
    RadioTap::option current_option();

    /**
     * \brief Gets the pointer at which the current option is located
     *
     * A past-the-end pointer may be returned in case of malformed input or
     * end of data. Its validity must be checked (e.g. using
     * \ref RadioTapParser.has_fields) before dereference.
     */
    const uint8_t* current_option_ptr() const;

    /**
     * \brief Advances to the next option
     *
     * If there's a namespace change, this will handle that as well.
     *
     * \return true iff advancing was successfull (e.g. false if we reached
     * the end of the header)
     */
    bool advance_field();

    /**
     * \brief Advances to the next namespace
     *
     * \return true iff advancing was successfull (e.g. false if we're currently
     * in the last namespace)
     */
    bool advance_namespace();

    /**
     * Gets the current namespace's flags
     */
    RadioTap::PresentFlags namespace_flags() const;

    /**
     * \brief Skips all fields until the provided one is found
     *
     * This will effectively move the current option pointer until the field is 
     * found or the end of the options list is reached
     *
     * \return true iff the field was foudn
     */
    bool skip_to_field(RadioTap::PresentFlags flag);

    /**
     * Indicates whether this RadioTap options buffer contains any fields set
     */
    bool has_fields() const;

    /**
     * \brief Indicates whether the provided field is set.
     *
     * This will look the field up in all flag sets and not just the current one
     */
    bool has_field(RadioTap::PresentFlags flag) const;
private:
    const uint8_t* find_options_start() const;
    bool advance_to_first_field();
    bool advance_to_next_field();
    bool skip_current_field();
    bool advance_to_next_namespace();
    const RadioTapFlags* get_flags_ptr() const;
    void load_current_flags();
    bool is_field_set(uint32_t bit, const RadioTapFlags* flags) const;

    const uint8_t* start_;
    const uint8_t* end_; 
    const uint8_t* current_ptr_;
    uint64_t current_bit_;
    uint32_t current_flags_;
    uint32_t namespace_index_;
    NamespaceType current_namespace_;
};

} // Utils
} // Tins

#endif // TINS_RADIOTAP_PARSER_H
