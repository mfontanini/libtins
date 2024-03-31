#include <algorithm>
#include <tins/exceptions.h>
#include <tins/internals.h>
#include <tins/memory_helpers.h>
#include <tins/rtp.h>

using std::logic_error;
using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

RTP::RTP()
: header_(), ext_header_(), padding_size_(0) {
    version(2);
}

RTP::RTP(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);

    small_uint<4> csrc_count_ = csrc_count();

    for (uint32_t i = 0; i < csrc_count_; ++i) {
        uint32_t csrc_id;
        stream.read(csrc_id);
        csrc_ids_.push_back(csrc_id);
    }

    if (extension_bit() == 1) {
        stream.read(ext_header_);
        for (uint32_t i = 0; i < extension_length(); ++i) {
            uint32_t data;
            stream.read(data);
            ext_data_.push_back(data);
        }
    }

    padding_size_ = 0;

    const uint8_t* data_ptr = stream.pointer();
    const size_t data_size = stream.size();

    if (padding_bit() == 1) {
        if (data_size > 0) {
            stream.skip(data_size - sizeof(uint8_t));
            stream.read(padding_size_);
        } else {
            throw malformed_packet();
        }

        if (padding_size() == 0) {
            throw malformed_packet();
        }
    }

    if (padding_size() > data_size) {
        throw malformed_packet();
    }

    if (data_size > padding_size()) {
        inner_pdu(
            Internals::pdu_from_flag(
                PDU::RAW,
                data_ptr,
                data_size - padding_size()
            )
        );
    }
}

uint32_t RTP::header_size() const {
    uint32_t extension_size = 0;
    if (extension_bit() == 1) {
        extension_size = sizeof(ext_header_) + (extension_length() * sizeof(uint32_t));
    }
    return static_cast<uint32_t>(sizeof(header_) + (csrc_ids_.size() * sizeof(uint32_t)) + extension_size);
}

void RTP::add_csrc_id(const uint32_t csrc_id) {
    small_uint<4> csrc_count_ = csrc_count();
    if (TINS_UNLIKELY(csrc_count_ >= 15)) {
        throw logic_error("Maximum number of CSRC IDs reached");
    }

    csrc_ids_.push_back(Endian::host_to_be(csrc_id));
    csrc_count(csrc_count_ + 1);
}

bool RTP::remove_csrc_id(const uint32_t csrc_id) {
    small_uint<4> csrc_count_ = csrc_count();
    if (csrc_count_ == 0) {
        return false;
    }

    csrc_ids_type::iterator iter = search_csrc_id_iterator(Endian::host_to_be(csrc_id));
    if (iter == csrc_ids_.end()) {
        return false;
    }

    csrc_ids_.erase(iter);
    csrc_count(csrc_count_ - 1);
    return true;
}

bool RTP::search_csrc_id(const uint32_t csrc_id) {
    csrc_ids_type::const_iterator iter = search_csrc_id_iterator(Endian::host_to_be(csrc_id));
    return (iter != csrc_ids_.cend());
}

RTP::csrc_ids_type::const_iterator RTP::search_csrc_id_iterator(const uint32_t csrc_id) const {
    return std::find(csrc_ids_.cbegin(), csrc_ids_.cend(), csrc_id);
}

RTP::csrc_ids_type::iterator RTP::search_csrc_id_iterator(const uint32_t csrc_id) {
    return std::find(csrc_ids_.begin(), csrc_ids_.end(), csrc_id);
}

void RTP::add_extension_data(const uint32_t value) {
    if (TINS_UNLIKELY(extension_length() >= 65535)) {
        throw logic_error("Maximum number of extension data reached");
    }

    extension_bit(1);
    ext_data_.push_back(Endian::host_to_be(value));
    extension_length(extension_length() + 1);
}

bool RTP::remove_extension_data(const uint32_t value) {
    if (extension_bit() == 0 || extension_length() == 0) {
        return false;
    }

    extension_header_data_type::iterator iter = search_extension_data_iterator(Endian::host_to_be(value));
    if (iter == ext_data_.end()) {
        return false;
    }

    ext_data_.erase(iter);

    extension_length(extension_length() - 1);

    if (extension_length() == 0) {
        extension_bit(0);
    }

    return true;
}

bool RTP::search_extension_data(const uint32_t value) {
    if (extension_bit() == 0 || extension_length() == 0) {
        return false;
    }

    extension_header_data_type::const_iterator iter = search_extension_data_iterator(Endian::host_to_be(value));
    return (iter != ext_data_.cend());
}

RTP::extension_header_data_type::const_iterator RTP::search_extension_data_iterator(const uint32_t data) const {
    return std::find(ext_data_.cbegin(), ext_data_.cend(), data);
}

RTP::extension_header_data_type::iterator RTP::search_extension_data_iterator(const uint32_t data) {
    return std::find(ext_data_.begin(), ext_data_.end(), data);
}

void RTP::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);
    stream.write(header_);

    for (auto csrc_id : csrc_ids_) {
        stream.write(csrc_id);
    }

    if (extension_bit() == 1) {
        stream.write(ext_header_);
        for (auto data : ext_data_) {
            stream.write(data);
        }
    }

    if (padding_bit() == 1) {
        if (padding_size() > 0) {
            if (inner_pdu()) {
                stream.skip(inner_pdu()->size());
            }
            stream.fill(padding_size() - 1, 0);
            stream.write(padding_size());
        } else {
            throw pdu_not_serializable();
        }
    }
}

} // Tins
