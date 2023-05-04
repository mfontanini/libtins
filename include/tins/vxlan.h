#ifndef TINS_VXLAN_H
#define TINS_VXLAN_H

#include <tins/pdu.h>
#include <tins/small_uint.h>

namespace Tins {

/** 
 * \class VXLAN
 * \brief Represents a VXLAN PDU.
 *
 * This class represents a VXLAN PDU.
 *
 * \sa RawPDU
 */
class TINS_API VXLAN : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::VXLAN;

    /**
     * \brief Constructs a VXLAN PDU.
     *
     * \param vni VXLAN Network Identifier.
     */
    VXLAN(const small_uint<24> vni = 0);

    /**
     * \brief Constructs a VXLAN object from a buffer and adds
     * the Ethernet II PDU.
     *
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    VXLAN(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the flags.
     */
    uint8_t get_flags() const { return Endian::be_to_host(header_.flags) >> 24; }

    /**
     * \brief Getter for the VNI.
     */
    small_uint<24> get_vni() const { return Endian::be_to_host(header_.vni) >> 8; }

    /**
     * \brief Setter for the flags.
     * \param new_flags The new flags.
     */
    void set_flags(uint8_t new_flags) { header_.flags = Endian::host_to_be(new_flags << 24); }

    /**
     * \brief Setter for the VNI.
     * \param new_vni The new VNI.
     */
    void set_vni(small_uint<24> new_vni) { header_.vni = Endian::host_to_be(new_vni << 8); }

    /**
     * \brief Returns the VXLAN frame's header length.
     * 
     * This method overrides PDU::header_size. This size includes the
     * payload and options size.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size
     */
    uint32_t header_size() const { return sizeof(header_); }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \sa PDU::clone
     */
    VXLAN *clone() const { return new VXLAN(*this); }

private:
    TINS_BEGIN_PACK
    struct vxlan_header {
        uint32_t flags;
        uint32_t vni;
    } TINS_END_PACK;

    void write_serialization(uint8_t* buffer, uint32_t total_sz);

    vxlan_header header_;
};

} // Tins

#endif // TINS_VXLAN_H
