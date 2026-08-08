#include <algorithm>
#include <tins/exceptions.h>
#include <tins/internals.h>
#include <tins/memory_helpers.h>
#include <tins/bfd.h>

using std::copy;
using std::invalid_argument;
using std::logic_error;
using std::min;
using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

BFD::BFD()
: header_(), auth_header_(), auth_data_md5_(), auth_data_sha1_() {
    version(1);
    length(sizeof(header_));
}

BFD::BFD(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);

    if (authentication_present()) {
        uint8_t candidate_auth_type = 0;
        uint8_t candidate_auth_len = 0;
        uint8_t candidate_auth_key_id = 0;
        stream.read(candidate_auth_type);
        stream.read(candidate_auth_len);

        BFD::AuthenticationType potential_auth_type = static_cast<BFD::AuthenticationType>(candidate_auth_type);

        size_t auth_header_size = sizeof(auth_header_.auth_type) + sizeof(auth_header_.auth_len);
        const uint8_t reserved = 0;

        switch (potential_auth_type) {
            case BFD::AuthenticationType::RESERVED:
                if (candidate_auth_len >= auth_header_size) {
                    auth_type(potential_auth_type);
                    auth_len(candidate_auth_len);
                    stream.skip(candidate_auth_len - auth_header_size);
                } else {
                    throw malformed_packet();
                }
                break;

            case BFD::AuthenticationType::SIMPLE_PASSWORD:
                auth_header_size += sizeof(auth_header_.auth_key_id);
                if ((candidate_auth_len < auth_header_size + 1) || (candidate_auth_len > auth_header_size + MAX_PASSWORD_SIZE)) {
                    throw malformed_packet();
                }
                stream.read(candidate_auth_key_id);
                auth_type(potential_auth_type);
                auth_len(candidate_auth_len);
                auth_key_id(candidate_auth_key_id);
                for (size_t i = 0; i < min(candidate_auth_len - auth_header_size, MAX_PASSWORD_SIZE); ++i) {
                    uint8_t password_byte = 0;
                    stream.read(password_byte);
                    password_.push_back(password_byte);
                }
                break;

            case BFD::AuthenticationType::KEYED_MD5:
            case BFD::AuthenticationType::METICULOUS_KEYED_MD5:
                auth_header_size += sizeof(auth_header_.auth_key_id) + sizeof(reserved) + sizeof(auth_data_md5_.sequence_number);
                if (candidate_auth_len != auth_header_size + MD5_DIGEST_SIZE) {
                    throw malformed_packet();
                }
                stream.read(candidate_auth_key_id);
                auth_type(potential_auth_type);
                auth_len(candidate_auth_len);
                auth_key_id(candidate_auth_key_id);
                stream.skip(sizeof(reserved));
                stream.read(auth_data_md5_);
                break;

            case BFD::AuthenticationType::KEYED_SHA1:
            case BFD::AuthenticationType::METICULOUS_KEYED_SHA1:
                auth_header_size += sizeof(auth_header_.auth_key_id) + sizeof(reserved) + sizeof(auth_data_sha1_.sequence_number);
                if (candidate_auth_len != auth_header_size + SHA1_HASH_SIZE) {
                    throw malformed_packet();
                }
                stream.read(candidate_auth_key_id);
                auth_type(potential_auth_type);
                auth_len(candidate_auth_len);
                auth_key_id(candidate_auth_key_id);
                stream.skip(sizeof(reserved));
                stream.read(auth_data_sha1_);
                break;

            default:
                throw malformed_packet();
        }
    }

    if (length() != header_size()) {
        throw malformed_packet();
    }
}

uint32_t BFD::header_size() const {
    uint32_t bfd_header_size = sizeof(header_);

    if (authentication_present()) {
        const size_t auth_header_size = sizeof(auth_header_.auth_type) + sizeof(auth_header_.auth_len);
        const uint8_t reserved = 0;
        bfd_header_size += auth_header_size;

        switch (auth_type()) {
            case BFD::AuthenticationType::RESERVED:
                if (auth_len() >= auth_header_size) {
                    bfd_header_size += auth_len() - auth_header_size;
                } else {
                    throw malformed_packet();
                }
                break;

            case BFD::AuthenticationType::SIMPLE_PASSWORD:
                bfd_header_size += sizeof(auth_header_.auth_key_id) + password_.size();
                break;

            case BFD::AuthenticationType::KEYED_MD5:
            case BFD::AuthenticationType::METICULOUS_KEYED_MD5:
                bfd_header_size += sizeof(auth_header_.auth_key_id) + sizeof(reserved) + sizeof(auth_data_md5_.sequence_number) + sizeof(auth_data_md5_.auth_value);
                break;

            case BFD::AuthenticationType::KEYED_SHA1:
            case BFD::AuthenticationType::METICULOUS_KEYED_SHA1:
                bfd_header_size += sizeof(auth_header_.auth_key_id) + sizeof(reserved) + sizeof(auth_data_sha1_.sequence_number) + sizeof(auth_data_sha1_.auth_value);
                break;

            default:
                throw logic_error("Unknown authentication type");
        }
    }

    return bfd_header_size;
}

const byte_array& BFD::password() const {
    if (auth_type() != BFD::AuthenticationType::SIMPLE_PASSWORD) {
        throw logic_error("Authentication type is not SIMPLE_PASSWORD");
    }

    return password_;
}

void BFD::password(const byte_array& password) {
    if (auth_type() != BFD::AuthenticationType::SIMPLE_PASSWORD) {
        throw logic_error("Authentication type is not SIMPLE_PASSWORD");
    }

    if (password.size() > MAX_PASSWORD_SIZE) {
        throw invalid_argument("Password is too long");
    } else if (password.empty()) {
        throw invalid_argument("Password is empty");
    }

    password_ = password;
}

uint32_t BFD::auth_sequence_number() const {
    switch (auth_type()) {
        case BFD::AuthenticationType::KEYED_MD5:
        case BFD::AuthenticationType::METICULOUS_KEYED_MD5:
            return Endian::be_to_host(auth_data_md5_.sequence_number);

        case BFD::AuthenticationType::KEYED_SHA1:
        case BFD::AuthenticationType::METICULOUS_KEYED_SHA1:
            return Endian::be_to_host(auth_data_sha1_.sequence_number);

        default:
            throw logic_error("Authentication type does not have a sequence number");
    }
}

void BFD::auth_sequence_number(uint32_t sequence_number) {
    switch (auth_type()) {
        case BFD::AuthenticationType::KEYED_MD5:
        case BFD::AuthenticationType::METICULOUS_KEYED_MD5:
            auth_data_md5_.sequence_number = Endian::host_to_be(sequence_number);
            break;

        case BFD::AuthenticationType::KEYED_SHA1:
        case BFD::AuthenticationType::METICULOUS_KEYED_SHA1:
            auth_data_sha1_.sequence_number = Endian::host_to_be(sequence_number);
            break;

        default:
            throw logic_error("Authentication type does not have a sequence number");
    }
}

const byte_array BFD::auth_md5_value() const {
    if (auth_type() != BFD::AuthenticationType::KEYED_MD5 && auth_type() != BFD::AuthenticationType::METICULOUS_KEYED_MD5) {
        throw logic_error("Authentication type is not MD5-based");
    }

    return byte_array(auth_data_md5_.auth_value, auth_data_md5_.auth_value + MD5_DIGEST_SIZE);
}

const byte_array BFD::auth_sha1_value() const {
    if (auth_type() != BFD::AuthenticationType::KEYED_SHA1 && auth_type() != BFD::AuthenticationType::METICULOUS_KEYED_SHA1) {
        throw logic_error("Authentication type is not SHA1-based");
    }

    return byte_array(auth_data_sha1_.auth_value, auth_data_sha1_.auth_value + SHA1_HASH_SIZE);
}

void BFD::auth_md5_value(const byte_array& auth_value) {
    if (auth_type() != BFD::AuthenticationType::KEYED_MD5 && auth_type() != BFD::AuthenticationType::METICULOUS_KEYED_MD5) {
        throw logic_error("Authentication type is not MD5-based");
    }

    if (auth_value.size() != MD5_DIGEST_SIZE) {
        throw invalid_argument("Invalid MD5 authentication value size");
    }

    copy(auth_value.begin(), auth_value.end(), auth_data_md5_.auth_value);
}

void BFD::auth_sha1_value(const byte_array& auth_value) {
    if (auth_type() != BFD::AuthenticationType::KEYED_SHA1 && auth_type() != BFD::AuthenticationType::METICULOUS_KEYED_SHA1) {
        throw logic_error("Authentication type is not SHA1-based");
    }

    if (auth_value.size() != SHA1_HASH_SIZE) {
        throw invalid_argument("Invalid SHA1 authentication value size");
    }

    copy(auth_value.begin(), auth_value.end(), auth_data_sha1_.auth_value);
}

void BFD::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);
    size_t packet_length = sizeof(header_);
    stream.write(header_);

    if (authentication_present()) {
        size_t auth_header_size = sizeof(auth_header_.auth_type) + sizeof(auth_header_.auth_len);
        const uint8_t reserved = 0;

        switch (auth_type()) {
            case BFD::AuthenticationType::RESERVED:
                if (auth_len() >= auth_header_size) {
                    stream.write(auth_header_.auth_type);
                    stream.write(auth_header_.auth_len);
                    for (size_t i = 0; i < auth_len() - auth_header_size; ++i) {
                        stream.write(reserved);
                    }
                    auth_header_size += auth_len() - auth_header_size;
                } else {
                    throw logic_error("Invalid authentication section length");
                }
                break;

            case BFD::AuthenticationType::SIMPLE_PASSWORD:
                if (password_.empty()) {
                    throw logic_error("Password is empty");
                }
                auth_header_size += sizeof(auth_header_.auth_key_id) + password_.size();
                if (auth_len() != auth_header_size) {
                    throw logic_error("Invalid authentication section length");
                }
                stream.write(auth_header_);
                for (size_t i = 0; i < password_.size(); ++i) {
                    stream.write(password_[i]);
                }
                break;

            case BFD::AuthenticationType::KEYED_MD5:
            case BFD::AuthenticationType::METICULOUS_KEYED_MD5:
                auth_header_size += sizeof(auth_header_.auth_key_id) + sizeof(reserved) + sizeof(auth_data_md5_.sequence_number) + sizeof(auth_data_md5_.auth_value);
                if (auth_len() != auth_header_size) {
                    throw logic_error("Invalid authentication section length");
                }
                stream.write(auth_header_);
                stream.write(reserved);
                stream.write(auth_data_md5_);
                break;

            case BFD::AuthenticationType::KEYED_SHA1:
            case BFD::AuthenticationType::METICULOUS_KEYED_SHA1:
                auth_header_size += sizeof(auth_header_.auth_key_id) + sizeof(reserved) + sizeof(auth_data_sha1_.sequence_number) + sizeof(auth_data_sha1_.auth_value);
                if (auth_len() != auth_header_size) {
                    throw logic_error("Invalid authentication section length");
                }
                stream.write(auth_header_);
                stream.write(reserved);
                stream.write(auth_data_sha1_);
                break;

            default:
                throw logic_error("Unknown authentication type");
        }

        packet_length += auth_header_size;
    }

    if (length() != packet_length) {
        throw logic_error("Invalid BFD packet length");
    }
}

} // Tins
