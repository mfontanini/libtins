#include <algorithm>
#include "icmp_extension.h"
#include "endianness.h"
#include "exceptions.h"

using std::runtime_error;

namespace Tins {

const uint32_t ICMPExtension::BASE_HEADER_SIZE = sizeof(uint16_t) + sizeof(uint8_t) * 2;

ICMPExtension::ICMPExtension(const uint8_t* buffer, uint32_t total_sz) {
    // Check for the base header (u16 length + u8 clss + u8 type)
    if (total_sz < BASE_HEADER_SIZE) {
        throw malformed_packet();
    }

    uint16_t length = Endian::be_to_host(*(const uint16_t*)buffer);
    buffer += sizeof(uint16_t);
    extension_class_ = *buffer++;
    extension_type_ = *buffer++;
    total_sz -= BASE_HEADER_SIZE;
    // Length is BASE_HEADER_SIZE + payload size, make sure it's valid
    if (length < BASE_HEADER_SIZE || length - BASE_HEADER_SIZE > total_sz) {
        throw malformed_packet();
    }
    length -= BASE_HEADER_SIZE;
    payload_.assign(buffer, buffer + length);
}

uint32_t ICMPExtension::extension_size() const {
    return BASE_HEADER_SIZE + payload_.size();
}

void ICMPExtension::serialize(uint8_t* buffer, uint32_t buffer_size) const {
    if (buffer_size < extension_size()) {
        throw runtime_error("Serialization buffer is too small");
    }
    *(uint16_t*)buffer = Endian::host_to_be<uint16_t>(extension_size());
    buffer += sizeof(uint16_t);
    *buffer = extension_class_;
    buffer += sizeof(uint8_t);
    *buffer = extension_type_;
    buffer += sizeof(uint8_t);
    copy(payload_.begin(), payload_.end(), buffer);
}

ICMPExtension::serialization_type ICMPExtension::serialize() const {
    serialization_type output(extension_size());
    serialize(&output[0], output.size());
    return output;
}

} // Tins
