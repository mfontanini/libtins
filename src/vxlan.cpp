#include <tins/internals.h>
#include <tins/memory_helpers.h>
#include <tins/small_uint.h>
#include <tins/vxlan.h>

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

VXLAN::VXLAN(const small_uint<24> vni) {
    set_flags(8);
    set_vni(vni);
}

VXLAN::VXLAN(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    // If there is any size left
    if (stream) {
        inner_pdu(
            Internals::pdu_from_flag(
                PDU::ETHERNET_II,
                stream.pointer(),
                stream.size()
            )
        );
    }
}

void VXLAN::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);
    stream.write(header_);
}

} // Tins
