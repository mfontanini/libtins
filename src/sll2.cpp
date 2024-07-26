#include <cstring>
#include <tins/detail/pdu_helpers.h>
#include <tins/exceptions.h>
#include <tins/memory_helpers.h>
#include <tins/sll2.h>

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

SLL2::SLL2() : header_() {}

SLL2::SLL2(const uint8_t *buffer, uint32_t total_sz) {
  InputMemoryStream stream(buffer, total_sz);
  stream.read(header_);
  if (stream) {
    inner_pdu(Internals::pdu_from_flag((Constants::Ethernet::e)protocol(),
                                       stream.pointer(), stream.size()));
  }
}

void SLL2::protocol(uint16_t new_protocol) {
  header_.protocol = Endian::host_to_be(new_protocol);
}

void SLL2::interface_index(uint32_t new_interface_index) {
  header_.interface_index = Endian::host_to_be(new_interface_index);
}

void SLL2::lladdr_type(uint16_t new_lladdr_type) {
  header_.lladdr_type = Endian::host_to_be(new_lladdr_type);
}

void SLL2::packet_type(uint8_t new_packet_type) {
  header_.packet_type = Endian::host_to_be(new_packet_type);
}

void SLL2::lladdr_len(uint8_t new_lladdr_len) {
  header_.lladdr_len = Endian::host_to_be(new_lladdr_len);
}

void SLL2::address(const address_type &new_address) {
  new_address.copy(header_.address);
}

uint32_t SLL2::header_size() const { return sizeof(header_); }

void SLL2::write_serialization(uint8_t *buffer, uint32_t total_sz) {
  OutputMemoryStream stream(buffer, total_sz);
  if (inner_pdu()) {
    Constants::Ethernet::e flag =
        Internals::pdu_flag_to_ether_type(inner_pdu()->pdu_type());
    protocol(static_cast<uint16_t>(flag));
  }
  stream.write(header_);
}

} // namespace Tins
