#ifndef TINS_ICMP_EXTENSION_H
#define TINS_ICMP_EXTENSION_H

#include <vector>
#include <stdint.h>

namespace Tins {

/**
 * \brief Class that represents an ICMP extension object
 */
class ICMPExtension {
public:
    typedef std::vector<uint8_t> payload_type;
    typedef std::vector<uint8_t> serialization_type;

    /**
     * \brief Constructs an ICMP extension from a buffer
     *
     * \param buffer The input buffer
     * \param total_sz The input buffer size
     */
    ICMPExtension(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the extension class field
     *
     * \return The extension class field value
     */
    uint8_t extension_class() const { return extension_class_; }

    /**
     * \brief Getter for the extension sub-type field
     *
     * \return The extension sub-type field value
     */
    uint8_t extension_type() const { return extension_type_; }

    /**
     * \brief Getter for the extension payload field
     *
     * \return The extension payload field value
     */
    const payload_type& payload() const { return payload_; }

    /**
     * \brief Gets the size of this ICMP extension
     *
     * This returns the basic header size + the payload size
     *
     * \return The size of this extension
     */
    uint32_t extension_size() const;

    /**
     * \brief Serializes this extension into a buffer
     *
     * \param buffer The output buffer in which to store the serialization
     * \param buffer_size The size of the output buffer
     */
    void serialize(uint8_t* buffer, uint32_t buffer_size) const;

    /**
     * \brief Serializes this ICMP extension object
     * 
     * \return The serialized ICMP extension
     */
    serialization_type serialize() const;
private:
    static const uint32_t BASE_HEADER_SIZE;

    payload_type payload_;
    uint8_t extension_class_, extension_type_;
};

} // Tins

#endif // TINS_ICMP_EXTENSION_H
