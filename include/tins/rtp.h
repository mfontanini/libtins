#ifndef TINS_RTP_H
#define TINS_RTP_H

#include <tins/endianness.h>
#include <tins/pdu.h>
#include <tins/pdu_option.h>
#include <tins/small_uint.h>

namespace Tins {

/**
 * \class RTP
 * \brief Represents a RTP PDU.
 *
 * This class represents a RTP PDU.
 *
 * \sa RawPDU
 */
class TINS_API RTP : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::RTP;

    /**
     * The type used to store CSRC identifiers.
     */
    typedef std::vector<uint32_t> csrc_ids_type;

    /**
     * The type used to store extension header data.
     */
    typedef std::vector<uint32_t> extension_header_data_type;

    /**
     * Default constructor.
     */
    RTP();

    /**
     * \brief Constructs a RTP object from a buffer.
     *
     * \param data The buffer from which this PDU will be constructed.
     * \param size The size of the data buffer.
     */
    RTP(const uint8_t* data, uint32_t size);

    /**
     * \brief Getter for the version.
     */
    small_uint<2> version() const { return header_.version; }

    /**
     * \brief Getter for the padding bit.
     */
    small_uint<1> padding_bit() const { return header_.padding; }

    /**
     * \brief Getter for the extension bit.
     */
    small_uint<1> extension_bit() const { return header_.extension; }

    /**
     * \brief Getter for the CSRC count.
     */
    small_uint<4> csrc_count() const { return header_.csrc_count; }

    /**
     * \brief Getter for the marker bit.
     */
    small_uint<1> marker_bit() const { return header_.marker; }

    /**
     * \brief Getter for the payload type.
     */
    small_uint<7> payload_type() const { return header_.payload_type; }

    /**
     * \brief Getter for the sequence number.
     */
    uint16_t sequence_number() const { return Endian::be_to_host(header_.seq_num); }

    /**
     * \brief Getter for the timestamp.
     */
    uint32_t timestamp() const { return Endian::be_to_host(header_.timestamp); }

    /**
     * \brief Getter for the SSRC identifier.
     */
    uint32_t ssrc_id() const { return Endian::be_to_host(header_.ssrc_id); }

    /**
     * \brief Getter for the CSRC identifiers.
     */
    const csrc_ids_type& csrc_ids() const {
        return csrc_ids_;
    }

    /**
     * \brief Getter for the padding size.
     */
    uint8_t padding_size() const { return padding_size_; }

    /**
     * \brief Getter for the extension header profile.
     */
    uint16_t extension_profile() const { return Endian::be_to_host(ext_header_.profile); }

    /**
     * \brief Getter for the extension header length.
     */
    uint16_t extension_length() const { return Endian::be_to_host(ext_header_.length); }

    /**
     * \brief Getter for the extension header data.
     */
    const extension_header_data_type& extension_data() const {
        return ext_data_;
    }

    /**
     * \brief Setter for the version.
     * \param version The new version.
     */
    void version(small_uint<2> version) { header_.version = version; }

    /**
     * \brief Setter for the extension bit.
     * \param extension The new extension bit.
     */
    void extension_bit(small_uint<1> extension) { header_.extension = extension; }

    /**
     * \brief Setter for the marker bit.
     * \param marker The new marker bit.
     */
    void marker_bit(small_uint<1> marker) { header_.marker = marker; }

    /**
     * \brief Setter for the payload type.
     * \param payload_type The new payload type.
     */
    void payload_type(small_uint<7> payload_type) { header_.payload_type = payload_type; }

    /**
     * \brief Setter for the sequence number.
     * \param seq_num The new sequence number.
     */
    void sequence_number(uint16_t seq_num) { header_.seq_num = Endian::host_to_be(seq_num); }

    /**
     * \brief Setter for the timestamp.
     * \param timestamp The new timestamp.
     */
    void timestamp(uint32_t timestamp) { header_.timestamp = Endian::host_to_be(timestamp); }

    /**
     * \brief Setter for the SSRC identifier.
     * \param ssrc_id The new SSRC identifier.
     */
    void ssrc_id(uint32_t ssrc_id) { header_.ssrc_id = Endian::host_to_be(ssrc_id); }

    /**
     * \brief Setter for the padding size.
     * \param size The new padding size.
     */
    void padding_size(uint8_t size) {
        padding_bit(size > 0);
        padding_size_ = size;
    }

    /**
     * \brief Setter for the extension header profile.
     * \param profile The new extension header profile.
     */
    void extension_profile(uint16_t profile) { ext_header_.profile = Endian::host_to_be(profile); }

    /**
     * \brief Adds a word of extension header data.
     *
     * The word is added after the last word of extension header data.
     *
     * \param value The value of the extension header data to be added.
     */
    void add_extension_data(const uint32_t value);

    /**
     * \brief Removes a word of extension header data.
     *
     * If there are multiple words of extension header data of the given value,
     * only the first one will be removed.
     *
     * \param value The value of the extension header data to be removed.
     * \return true if the extension header data was removed, false otherwise.
     */
    bool remove_extension_data(const uint32_t value);

    /**
     * \brief Searches for extension header data that matches the given value.
     * \param value The extension header data to be searched.
     * \return true if the extension header data was found, false otherwise.
     */
    bool search_extension_data(const uint32_t value);

    /**
     * \brief Adds a CSRC identifier.
     *
     * The CSRC identifier is added after the last CSRC identifier in the extension
     * header.
     *
     * \param csrc_id The CSRC identifier to be added
     */
    void add_csrc_id(const uint32_t csrc_id);

    /**
     * \brief Removes a CSRC identifier.
     *
     * If there are multiple CSRC identifiers of the given value, only the first one
     * will be removed.
     *
     * \param value The value of the CSRC identifier to be removed.
     * \return true if the CSRC identifier was removed, false otherwise.
     */
    bool remove_csrc_id(const uint32_t value);

    /**
     * \brief Searches for a CSRC identifier that matches the given value.
     * \param value The CSRC identifier to be searched.
     * \return true if the CSRC identifier was found, false otherwise.
     */
    bool search_csrc_id(const uint32_t value);

    /**
     * \brief Returns the RTP packet's header length.
     *
     * This method overrides PDU::header_size.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Returns the RTP packet's trailer length.
     *
     * This method overrides PDU::trailer_size.
     *
     * \return An uint32_t with the trailer's size.
     * \sa PDU::trailer_size
     */
    uint32_t trailer_size() const { return static_cast<uint32_t>(padding_size_); }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \sa PDU::clone
     */
    RTP *clone() const { return new RTP(*this); }

private:
    TINS_BEGIN_PACK
    struct rtp_header {
    #if TINS_IS_BIG_ENDIAN
        uint16_t version:2,
                 padding:1,
                 extension:1,
                 csrc_count:4,
                 marker:1,
                 payload_type:7;
    #elif TINS_IS_LITTLE_ENDIAN
        uint16_t csrc_count:4,
                 extension:1,
                 padding:1,
                 version:2,
                 payload_type:7,
                 marker:1;
    #endif
        uint16_t seq_num;
        uint32_t timestamp;
        uint32_t ssrc_id;
    } TINS_END_PACK;

    TINS_BEGIN_PACK
    struct rtp_extension_header {
        uint16_t profile;
        uint16_t length;
    } TINS_END_PACK;

    void write_serialization(uint8_t* buffer, uint32_t size);
    csrc_ids_type::const_iterator search_csrc_id_iterator(const uint32_t csrc_id) const;
    csrc_ids_type::iterator search_csrc_id_iterator(const uint32_t csrc_id);
    extension_header_data_type::const_iterator search_extension_data_iterator(const uint32_t data) const;
    extension_header_data_type::iterator search_extension_data_iterator(const uint32_t data);

    /**
     * \brief Setter for the padding bit.
     * \param padding The new padding bit.
     */
    void padding_bit(small_uint<1> padding) { header_.padding = padding; }

    /**
     * \brief Setter for the CSRC count. Hidden from the public interface.
     * \param csrc_count The new CSRC count.
     */
    void csrc_count(small_uint<4> csrc_count) { header_.csrc_count = csrc_count; }

    /**
     * \brief Setter for the extension header length. Hidden from the public interface.
     * \param length The new extension header length.
     */
    void extension_length(uint16_t length) { ext_header_.length = Endian::host_to_be(length); }

    rtp_header header_;
    csrc_ids_type csrc_ids_;
    rtp_extension_header ext_header_;
    extension_header_data_type ext_data_;
    uint8_t padding_size_;
};

} // Tins

#endif // TINS_RTP_H