#ifndef TINS_SLL2_H
#define TINS_SLL2_H

#include <cstdint>
#include <tins/endianness.h>
#include <tins/hw_address.h>
#include <tins/macros.h>
#include <tins/pdu.h>
#include <vector>

namespace Tins {

/**
 * \class SLL2
 * \brief Represents a Linux Cooked Capture v2 (SLL2) PDU.
 *
 * https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
 *
 */
class TINS_API SLL2 : public PDU {
public:
  /**
   * This PDU's flag.
   */
  static const PDU::PDUType pdu_flag = PDU::SLL2;

  /**
   *  The type of the address type
   */
  typedef HWAddress<8> address_type;

  /**
   * Default constructor
   */
  SLL2();

  /**
   * \brief Constructs a SLL2 object from a buffer and adds all
   * identifiable PDUs found in the buffer as children of this one.
   *
   * If the next PDU is not recognized, then a RawPDU is used.
   *
   * If there is not enough size for a SLL header in the
   * buffer, a malformed_packet exception is thrown.
   *
   * \param buffer The buffer from which this PDU will be constructed.
   * \param total_sz The total size of the buffer.
   */
  SLL2(const uint8_t *buffer, uint32_t total_sz);

  // Getters

  /**
   *  \brief Getter for the Protocol field.
   *  \return The stored Protocol field value.
   */
  uint16_t protocol() const { return Endian::be_to_host(header_.protocol); }

  /**
   *  \brief Getter for the Interface Index field.
   *  \return The stored Interface Index field value.
   */
  uint32_t interface_index() const {
    return Endian::be_to_host(header_.interface_index);
  }

  /**
   *  \brief Getter for the LLADDR Type field.
   *  \return The stored LLADDR Type field value.
   */
  uint16_t lladdr_type() const {
    return Endian::be_to_host(header_.lladdr_type);
  }

  /**
   *  \brief Getter for the Packet Type field.
   *  \return The stored Packet Type field value.
   */
  uint8_t packet_type() const {
    return Endian::be_to_host(header_.packet_type);
  }

  /**
   *  \brief Getter for the LLADDR Length field.
   *  \return The stored LLADDR Length field value.
   */
  uint8_t lladdr_len() const { return Endian::be_to_host(header_.lladdr_len); }

  /**
   *  \brief Getter for the Address field.
   *  \return The stored Address field value.
   */
  address_type address() const { return header_.address; }

  /**
   * \brief Getter for the PDU's type.
   * \sa PDU::pdu_type
   */
  PDUType pdu_type() const { return pdu_flag; }

  // Setters

  /**
   *  \brief Setter for the Protocol field.
   *  \param new_protocol The new Protocol field value.
   */
  void protocol(uint16_t new_protocol);

  /**
   *  \brief Setter for the Interface Index field.
   *  \param new_interface_index The new Interface Index field value.
   */
  void interface_index(uint32_t new_interface_index);

  /**
   *  \brief Setter for the LLADDR Type field.
   *  \param new_lladdr_type The new LLADDR Type field value.
   */
  void lladdr_type(uint16_t new_lladdr_type);

  /**
   *  \brief Setter for the Packet Type field.
   *  \param new_packet_type The new Packet Type field value.
   */
  void packet_type(uint8_t new_packet_type);

  /**
   *  \brief Setter for the LLADDR Length field.
   *  \param new_lladdr_len The new LLADDR Length field value.
   */
  void lladdr_len(uint8_t new_lladdr_len);

  /**
   *  \brief Setter for the Address field.
   *  \param new_address The new Address field value.
   */
  void address(const address_type &new_address);

  /**
   * \brief Returns the header size.
   *
   * This method overrides PDU::header_size. \sa PDU::header_size
   */
  uint32_t header_size() const;

  /**
   * \sa PDU::clone
   */
  SLL2 *clone() const { return new SLL2(*this); }

private:
  TINS_BEGIN_PACK
  struct sll2_header {
    uint16_t protocol, reserved_mbz;
    uint32_t interface_index;
    uint16_t lladdr_type;
    uint8_t packet_type, lladdr_len;
    uint8_t address[8];
  } TINS_END_PACK;

  void write_serialization(uint8_t *buffer, uint32_t total_sz);

  sll2_header header_;
};
} // namespace Tins

#endif // TINS_SLL2_H
