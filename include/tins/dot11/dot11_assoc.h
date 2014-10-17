/*
 * Copyright (c) 2014, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "../config.h"

#if !defined(TINS_DOT11_DOT11_ASSOC_H) && defined(HAVE_DOT11)
#define TINS_DOT11_DOT11_ASSOC_H

#include "../dot11/dot11_mgmt.h"

namespace Tins {
/**
 * \brief Class representing a Disassociation frame in the IEEE 802.11 Protocol.
 *
 */
class Dot11Disassoc : public Dot11ManagementFrame {
public:
   /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_DIASSOC;

    /**
     * \brief Constructor for creating a 802.11 Disassociation.
     *
     * Constructs a 802.11 Disassociation taking the destination
     * and source hardware address.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11Disassoc(const address_type &dst_hw_addr = address_type(), 
                const address_type &src_hw_addr = address_type());

    /**
     * \brief Constructs a Dot11Disassoc object from a buffer and 
     * adds all identifiable PDUs found in the buffer as children 
     * of this one.
     *
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for the header in the buffer
     * or the input data is malformed, a malformed_packet exception 
     * is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11Disassoc(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Getter for the reason code field.
     *
     * \return The stored reason code.
     */
    uint16_t reason_code() const { return Endian::le_to_host(_body.reason_code); }

    /**
     * \brief Setter for the reason code field.
     *
     * \param new_reason_code The reason code to be set.
     */
    void reason_code(uint16_t new_reason_code);

    /**
     * \brief Returns the frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Check wether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11Disassoc *clone() const {
        return new Dot11Disassoc(*this);
    }
private:
    struct DisassocBody {
        uint16_t reason_code;
    };

    uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

    DisassocBody _body;
};

/**
 * \brief Class representing an Association Request frame in the IEEE 802.11 Protocol.
 *
 */
class Dot11AssocRequest : public Dot11ManagementFrame {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_ASSOC_REQ;

    /**
     * \brief Constructor for creating a 802.11 Association Request.
     *
     * Constructs a 802.11 Association Request taking the
     * destination and source hardware address.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11AssocRequest(const address_type &dst_hw_addr = address_type(), 
                    const address_type &src_hw_addr = address_type());

    /**
     * \brief Constructs a Dot11AssocRequest object from a buffer 
     * and adds all identifiable PDUs found in the buffer as children 
     * of this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for the header in the buffer
     * or the input data is malformed, a malformed_packet exception 
     * is thrown.
     *
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11AssocRequest(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Getter for the Capabilities Information.
     *
     * \return A constant refereence to the stored Capabilities 
     * Information field.
     */
    const capability_information& capabilities() const { return _body.capability;}

    /**
     * \brief Getter for the Capabilities Information.
     *
     * \return A refereence to the stored Capabilities Information 
     * field.
     */
    capability_information& capabilities() { return _body.capability;}

    /**
     * \brief Getter for the listen interval field.
     *
     * \return The stored listen interval field.
     */
    uint16_t listen_interval() const { return Endian::le_to_host(_body.listen_interval); }

    /**
     * \brief Setter for the listen interval field.
     *
     * \param new_listen_interval The listen interval to be set.
     */
    void listen_interval(uint16_t new_listen_interval);

    /**
     * \brief Returns the frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Check wether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11AssocRequest *clone() const {
        return new Dot11AssocRequest(*this);
    }
private:
    struct AssocReqBody {
        capability_information capability;
        uint16_t listen_interval;
    };

    uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

    AssocReqBody _body;
};

/**
 * \brief Class representing an Association Response frame in the IEEE 802.11 Protocol.
 *
 */
class Dot11AssocResponse : public Dot11ManagementFrame {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_ASSOC_RESP;

    /**
     * \brief Constructor for creating a 802.11 Association Response.
     *
     * Constructors a 802.11 Association Response taking destination 
     * and source hardware address.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11AssocResponse(const address_type &dst_hw_addr = address_type(), 
                        const address_type &src_hw_addr = address_type());

    /**
     * \brief Constructor which creates a Dot11AssocResponse object 
     * from a buffer and adds all identifiable PDUs found in the 
     * buffer as children of this one.
     *
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for the header in the buffer
     * or the input data is malformed, a malformed_packet exception 
     * is thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11AssocResponse(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Getter for the Capabilities Information field.
     *
     * \return A constant reference to the stored Capabilities 
     * Information field.
     */
    const capability_information& capabilities() const { return _body.capability;}

    /**
     * \brief Getter for the Capabilities Information field.
     *
     * \return A reference to the stored Capabilities 
     * Information field.
     */
    capability_information& capabilities() { return _body.capability;}

    /**
     * \brief Getter for the status code field.
     *
     * \return The stored status code.
     */
    uint16_t status_code() const { return Endian::le_to_host(_body.status_code); }

    /**
     * \brief Getter for the AID field.
     *
     * \return The stored AID field.
     */
    uint16_t aid() const { return Endian::le_to_host(_body.aid); }

    /**
     * \brief Setter for the status code.
     *
     * \param new_status_code The status code to be set.
     */
    void status_code(uint16_t new_status_code);

    /**
     * \brief Setter for the AID field.
     *
     * \param new_aid The AID value to be set.
     */
    void aid(uint16_t new_aid);

    /**
     * \brief Returns the frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Check wether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11AssocResponse *clone() const {
        return new Dot11AssocResponse(*this);
    }
private:
    struct AssocRespBody {
        capability_information capability;
        uint16_t status_code;
        uint16_t aid;
    };

    uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

    AssocRespBody _body;
};

/**
 * \brief Class representing an ReAssociation Request frame in the IEEE 802.11 Protocol.
 *
 */
class Dot11ReAssocRequest : public Dot11ManagementFrame {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_REASSOC_REQ;

    /**
     * \brief Constructor for creating a 802.11 ReAssociation Request.
     *
     * Constructors a 802.11 Association Request taking the destination 
     * and source hardware address.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11ReAssocRequest(const address_type &dst_hw_addr = address_type(), 
                        const address_type &src_hw_addr = address_type());

    /**
     * \brief Constructs a Dot11AssocRequest object from a buffer 
     * and adds all identifiable PDUs found in the buffer as 
     * children of this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for the header in the buffer
     * or the input data is malformed, a malformed_packet exception 
     * is thrown.
     *
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11ReAssocRequest(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Getter for the Capabilities Information.
     *
     * \return A constant reference to the stored Capabilities 
     * Information field.
     */
    const capability_information& capabilities() const { return _body.capability;}

    /**
     * \brief Getter for the Capabilities Information.
     *
     * \return A reference to the stored Capabilities Information 
     * field.
     */
    capability_information& capabilities() { return _body.capability;}

    /**
     * \brief Getter for the listen interval field.
     *
     * \return The stored listen interval.
     */
    uint16_t listen_interval() const { return Endian::le_to_host(_body.listen_interval); }

    /**
     * \brief Getter for the current ap field.
     *
     * \return The current ap.
     */
    address_type current_ap() const { return _body.current_ap; }

    /**
     * \brief Setter for the listen interval field.
     *
     * \param new_listen_interval The listen interval to be set.
     */
    void listen_interval(uint16_t new_listen_interval);

    /**
     * \brief Setter for the current ap.
     *
     * \param new_current_ap The address of the current ap.
     */
    void current_ap(const address_type &new_current_ap);

    /**
     * \brief Returns the frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Check wether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11ReAssocRequest *clone() const {
        return new Dot11ReAssocRequest(*this);
    }
private:
    struct ReAssocReqBody {
        capability_information capability;
        uint16_t listen_interval;
        uint8_t current_ap[address_type::address_size];
    };

    uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

    ReAssocReqBody _body;
};

/**
 * \brief IEEE 802.11 ReAssociation Response frame.
 *
 */
class Dot11ReAssocResponse : public Dot11ManagementFrame {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_REASSOC_RESP;

    /**
     * \brief Constructor for creating a 802.11 Association Response.
     *
     * Constructs a 802.11 ReAssociation Response taking the 
     * destination and source hardware address.
     *
     * \param dst_hw_addr The destination hardware address.
     * \param src_hw_addr The source hardware address.
     */
    Dot11ReAssocResponse(const address_type &dst_hw_addr = address_type(), 
                        const address_type &src_hw_addr = address_type());

    /**
     * \brief Constructs a Dot11ReAssocResponse object from a buffer 
     * and adds all identifiable PDUs found in the buffer as children 
     * of this one.
     * 
     * If the next PDU is not recognized, then a RawPDU is used.
     * 
     * If there is not enough size for the header in the buffer
     * or the input data is malformed, a malformed_packet exception 
     * is thrown.
     *
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    Dot11ReAssocResponse(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief Getter for the Capabilities Information.
     *
     * \return A constant reference to the stored Capabilities 
     * Information field.
     */
    const capability_information& capabilities() const { return _body.capability;}

    /**
     * \brief Getter for the Capabilities Information.
     *
     * \return A reference to the stored Capabilities Information 
     * field.
     */
    capability_information& capabilities() { return _body.capability;}

    /**
     * \brief Getter for the status code field.
     *
     * \return The stored status code.
     */
    uint16_t status_code() const { return Endian::le_to_host(_body.status_code); }

    /**
     * \brief Getter for the AID field.
     *
     * \return The stored AID field value.
     */
    uint16_t aid() const { return Endian::le_to_host(_body.aid); }

    /**
     * \brief Setter for the status code field.
     *
     * \param new_status_code The status code to be set.
     */
    void status_code(uint16_t new_status_code);

    /**
     * \brief Setter for the AID field.
     *
     * \param new_aid The AID to be set.
     */
    void aid(uint16_t new_aid);

    /**
     * \brief Returns the frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \brief Check wether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11ManagementFrame::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11ReAssocResponse *clone() const {
        return new Dot11ReAssocResponse(*this);
    }
private:
    struct ReAssocRespBody {
        capability_information capability;
        uint16_t status_code;
        uint16_t aid;
    };

    uint32_t write_fixed_parameters(uint8_t *buffer, uint32_t total_sz);

    ReAssocRespBody _body;
};
} // namespace Tins

#endif // TINS_DOT11_DOT11_ASSOC_H
