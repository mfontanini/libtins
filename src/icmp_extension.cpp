#include <algorithm>
#include <cstring>
#include "icmp_extension.h"
#include "exceptions.h"
#include "utils.h"

using std::runtime_error;

namespace Tins {

const uint32_t ICMPExtension::BASE_HEADER_SIZE = sizeof(uint16_t) + sizeof(uint8_t) * 2;

// ICMPExtension class

ICMPExtension::ICMPExtension() 
: extension_class_(0), extension_type_(0) {

} 

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

void ICMPExtension::extension_class(uint8_t value) {
    extension_class_ = value;
}

void ICMPExtension::extension_type(uint8_t value) {
    extension_type_ = value;
}

void ICMPExtension::payload(const payload_type& value) {
    payload_ = value;
}

uint32_t ICMPExtension::size() const {
    return BASE_HEADER_SIZE + payload_.size();
}

void ICMPExtension::serialize(uint8_t* buffer, uint32_t buffer_size) const {
    if (buffer_size < size()) {
        throw runtime_error("Serialization buffer is too small");
    }
    *(uint16_t*)buffer = Endian::host_to_be<uint16_t>(size());
    buffer += sizeof(uint16_t);
    *buffer = extension_class_;
    buffer += sizeof(uint8_t);
    *buffer = extension_type_;
    buffer += sizeof(uint8_t);
    copy(payload_.begin(), payload_.end(), buffer);
}

ICMPExtension::serialization_type ICMPExtension::serialize() const {
    serialization_type output(size());
    serialize(&output[0], output.size());
    return output;
}

// ICMPExtensionsStructure class

const uint32_t ICMPExtensionsStructure::BASE_HEADER_SIZE = sizeof(uint16_t) * 2;

ICMPExtensionsStructure::ICMPExtensionsStructure() 
: version_and_reserved_(0x2000), checksum_(0) {

}

ICMPExtensionsStructure::ICMPExtensionsStructure(const uint8_t* buffer, uint32_t total_sz) {
    if (total_sz < BASE_HEADER_SIZE) {
        throw malformed_packet();
    }

    version_and_reserved_ = *(const uint16_t*)buffer;
    buffer += sizeof(uint16_t);
    checksum_ = *(const uint16_t*)buffer;
    buffer += sizeof(uint16_t);
    total_sz -= BASE_HEADER_SIZE;
    while (total_sz > 0) {
        extensions_.push_back(ICMPExtension(buffer, total_sz));
        uint16_t size = Endian::be_to_host(*(const uint16_t*)buffer);
        total_sz -= size;
    }
}

void ICMPExtensionsStructure::reserved(small_uint<12> value) {
    uint16_t current_value = version_and_reserved_;
    current_value &= 0xf000;
    current_value |= value;
    version_and_reserved_ = Endian::host_to_be(current_value);
}

void ICMPExtensionsStructure::version(small_uint<4> value) {
    uint16_t current_value = Endian::be_to_host(version_and_reserved_);
    current_value &= 0xfff;
    current_value |= value << 12;
    version_and_reserved_ = Endian::host_to_be(current_value);   
}

bool ICMPExtensionsStructure::validate_extensions(const uint8_t* buffer, uint32_t total_sz) {
    if (total_sz < BASE_HEADER_SIZE) {
        return false;
    }
    uint16_t checksum = *(const uint16_t*)(buffer + sizeof(uint16_t));
    // The buffer is read only, so we can't set the initial checksum to 0. Therefore, 
    // we sum the first 2 bytes and then the payload
    uint32_t actual_checksum = *(const uint16_t*)buffer;
    buffer += BASE_HEADER_SIZE;
    total_sz -= BASE_HEADER_SIZE;
    // Now do the checksum over the payload
    actual_checksum += Utils::sum_range(buffer, buffer + total_sz);
    return checksum == static_cast<uint16_t>(~actual_checksum);
}

uint32_t ICMPExtensionsStructure::size() const {
    typedef extensions_type::const_iterator iterator;
    uint32_t output = BASE_HEADER_SIZE;
    for (iterator iter = extensions_.begin(); iter != extensions_.end(); ++iter) {
        output += iter->size();
    }
    return output;
}

void ICMPExtensionsStructure::serialize(uint8_t* buffer, uint32_t buffer_size) {
    const uint32_t structure_size = size();
    if (buffer_size < structure_size) {
        throw malformed_packet();
    }
    uint8_t* original_ptr = buffer;
    memcpy(buffer, &version_and_reserved_, sizeof(version_and_reserved_));
    buffer += sizeof(uint16_t);
    // Make checksum 0, for now, we'll compute it at the end
    memset(buffer, 0, sizeof(uint16_t));
    buffer += sizeof(uint16_t);
    buffer_size -= BASE_HEADER_SIZE;

    typedef extensions_type::const_iterator iterator;
    for (iterator iter = extensions_.begin(); iter != extensions_.end(); ++iter) {
        iter->serialize(buffer, buffer_size);
        buffer += iter->size();
        buffer_size -= iter->size();
    }
    uint16_t checksum = ~Utils::sum_range(original_ptr, original_ptr + structure_size);
    memcpy(original_ptr + sizeof(uint16_t), &checksum, sizeof(checksum));
    checksum_ = checksum;
}

ICMPExtensionsStructure::serialization_type ICMPExtensionsStructure::serialize() {
    serialization_type output(size());
    serialize(&output[0], output.size());
    return output;
}

} // Tins
