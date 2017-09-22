/*
 * Copyright (c) 2017, Matias Fontanini
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

#include <tins/config.h>

#if !defined(TINS_DOT11_DOT11_CONTROL_H) && defined(TINS_HAVE_DOT11)

#define TINS_DOT11_DOT11_CONTROL_H

#include <tins/dot11/dot11_base.h>
#include <tins/macros.h>

namespace Tins {
/**
 * \brief Represents an IEEE 802.11 control frame.
 */
class TINS_API Dot11Control : public Dot11 {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_CONTROL;
    
    /**
     * \brief Constructor for creating a 802.11 control frame PDU
     *
     * Constructs a 802.11 Control PDU taking the destination and 
     * source hardware addresses.
     *
     * \param dst_addr The destination hardware address.
     */
    Dot11Control(const address_type& dst_addr = address_type());

    /**
     * \brief Constructs a Dot11Control object from a buffer and
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
    Dot11Control(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11::matches_flag(flag);
    }
};

/**
 * \brief Class that represents an abstraction of the 802.11 control frames
 * that contain a target address.
 */
class TINS_API Dot11ControlTA : public Dot11Control {
public:
    /**
     * \brief Getter for the target address field.
     */
    address_type target_addr() const {
        return taddr_;
    }

    /**
     * \brief Setter for the target address field.
     * \param addr The new target address.
     */
    void target_addr(const address_type& addr);
protected:
    /**
     * \brief Constructor for creating a 802.11 control frame TA PDU
     *
     * Constructs a 802.11 PDU taking the destination and source 
     * hardware addresses.
     *
     * \param dst_addr The destination hardware address.
     * \param target_addr The source hardware address.
     */
    Dot11ControlTA(const address_type& dst_addr = address_type(), 
                const address_type& target_addr = address_type());

    /**
     * \brief Constructs a Dot11ControlTA object from a buffer and
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
    Dot11ControlTA(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Returns the 802.11 frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;
protected:
    /**
     * \brief Getter for the control ta additional fields size.
     */
    uint32_t controlta_size() const { 
        return static_cast<uint32_t>(taddr_.size() + sizeof(dot11_header)); 
    }

    void write_ext_header(Memory::OutputMemoryStream& stream);
private:

    address_type taddr_;
};

/**
 * \brief IEEE 802.11 RTS frame.
 */
class TINS_API Dot11RTS : public Dot11ControlTA {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_RTS;

    /**
     * \brief Constructor for creating a 802.11 RTS frame PDU
     *
     * Constructs a 802.11 RTS PDU taking the destination and source
     * hardware addresses.
     *
     * \param dst_addr The destination hardware address.
     * \param target_addr The source hardware address.
     */
    Dot11RTS(const address_type& dst_addr = address_type(), 
             const address_type& target_addr = address_type());
                
    /**
     * \brief Constructs a Dot11RTS object from a buffer and adds all 
     * identifiable PDUs found in the buffer as children of this one.
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
    Dot11RTS(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11RTS* clone() const {
        return new Dot11RTS(*this);
    }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11Control::matches_flag(flag);
    }
};

class TINS_API Dot11PSPoll : public Dot11ControlTA {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_PS_POLL;

    /**
     * \brief Constructor for creating a 802.11 PS-Poll frame PDU
     *
     * Constructs a 802.11 PDU taking the destination and source 
     * hardware addresses.
     *
     * \param dst_addr The destination hardware address.
     * \param target_addr The source hardware address.
     */
    Dot11PSPoll(const address_type& dst_addr = address_type(), 
                const address_type& target_addr = address_type());

    /**
     * \brief Constructs a Dot11PSPoll object from a buffer and
     * adds all identifiable PDUs found in the buffer as children of 
     * this one.
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
    Dot11PSPoll(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11PSPoll* clone() const {
        return new Dot11PSPoll(*this);
    }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
       return flag == pdu_flag || Dot11Control::matches_flag(flag);
    }
};

class TINS_API Dot11CFEnd : public Dot11ControlTA {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_CF_END;

    /**
     * \brief Constructor for creating a 802.11 CF-End frame PDU
     *
     * Constructs a 802.11 PDU taking the destination and source 
     * hardware addresses.
     *
     * \param dst_addr The destination hardware address.
     * \param target_addr The source hardware address.
     */
    Dot11CFEnd(const address_type& dst_addr = address_type(), 
               const address_type& target_addr = address_type());
                
    /**
     * \brief Constructs a Dot11CFEnd object from a buffer and adds 
     * all identifiable PDUs found in the buffer as children of this 
     * one.
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
    Dot11CFEnd(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11CFEnd* clone() const {
        return new Dot11CFEnd(*this);
    }

     /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
        return flag == pdu_flag || Dot11Control::matches_flag(flag);
    }
};

class TINS_API Dot11EndCFAck : public Dot11ControlTA {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_END_CF_ACK;

    /**
     * \brief Constructor for creating a 802.11 End-CF-Ack frame PDU
     *
     * Constructs a 802.11 PDU taking the destination and source 
     * hardware addresses.
     * 
     * \param dst_addr The destination hardware address.
     * \param target_addr The source hardware address.
     */
    Dot11EndCFAck(const address_type& dst_addr = address_type(), 
                  const address_type& target_addr = address_type());

    /**
     * \brief Constructs a Dot11EndCFAck frame object from a buffer 
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
    Dot11EndCFAck(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11EndCFAck* clone() const {
        return new Dot11EndCFAck(*this);
    }

     /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
        return flag == pdu_flag || Dot11Control::matches_flag(flag);
    }
};

class TINS_API Dot11Ack : public Dot11Control {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_ACK;

    /**
     * \brief Constructor for creating a 802.11 Ack frame PDU
     *
     * Constructs a 802.11 PDU taking the destination and source 
     * hardware addresses.
     *
     * \param dst_addr The destination hardware address.
     */
    Dot11Ack(const address_type& dst_addr = address_type());

    /**
     * \brief Constructs a Dot11Ack frame object from a buffer and
     * adds all identifiable PDUs found in the buffer as children of 
     * this one.
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
    Dot11Ack(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11Ack* clone() const {
        return new Dot11Ack(*this);
    }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
        return flag == pdu_flag || Dot11Control::matches_flag(flag);
    }
};

/**
 * \brief Class that represents an 802.11 Block Ack Request PDU.
 */
class TINS_API Dot11BlockAckRequest : public Dot11ControlTA {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_BLOCK_ACK_REQ;

    /**
     * \brief Constructor for creating a 802.11 Block Ack request frame PDU
     *
     * Constructs a 802.11 PDU taking the destination and source 
     * hardware addresses.
     * 
     * \param dst_addr The destination hardware address.
     * \param target_addr The source hardware address.
     */
    Dot11BlockAckRequest(const address_type& dst_addr = address_type(), 
                         const address_type& target_addr = address_type());

    /**
     * \brief Constructs a Dot11BlockAckRequest object from a buffer 
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
    Dot11BlockAckRequest(const uint8_t* buffer, uint32_t total_sz);

    /* Getter */

    /**
     * \brief Getter for the bar control field.
     * \return The stored bar control field.
     */
    small_uint<4> bar_control() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return bar_control_ & 0xf; 
        #else
        return (bar_control_ >> 8) & 0xf; 
        #endif
    }

    /**
     * \brief Getter for the start sequence field.
     * \return The stored start sequence.
     */
    small_uint<12> start_sequence() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return (start_sequence_ >> 4) & 0xfff; 
        #else
        return (Endian::le_to_host<uint16_t>(start_sequence_) >> 4) & 0xfff; 
        #endif
    }
    
    /**
     * \brief Getter for the fragment number field.
     * \return The stored fragment number field.
     */
    small_uint<4> fragment_number() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return start_sequence_ & 0xf; 
        #else
        return (start_sequence_ >> 8) & 0xf; 
        #endif
    }
    
    /**
     * \brief Returns the 802.11 frame's header length.
     *
     * \return The header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /* Setter */

    /**
     * \brief Setter for the bar control field.
     * \param bar The bar control field to be set.
     */
    void bar_control(small_uint<4> bar);

    /**
     * \brief Setter for the start sequence field.
     * \param bar The start sequence field to be set.
     */
    void start_sequence(small_uint<12> seq);
    
    /**
     * \brief Setter for the fragment number field.
     * \param frag The fragment number field to be set.
     */
    void fragment_number(small_uint<4> frag);

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11BlockAckRequest* clone() const {
        return new Dot11BlockAckRequest(*this);
    }

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
        return flag == pdu_flag || Dot11Control::matches_flag(flag);
    }
protected:
    void write_ext_header(Memory::OutputMemoryStream& stream);
private:
    uint16_t bar_control_;
    uint16_t start_sequence_;
};

/**
 * \brief Class that represents an 802.11 block ack frame.
 */
class TINS_API Dot11BlockAck : public Dot11ControlTA {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::DOT11_BLOCK_ACK;
    
    /**
     * The size of the bitmap field.
     */
    static const size_t bitmap_size = 8;

    /**
     * \brief Constructor for creating a 802.11 Block Ack frame PDU
     *
     * Constructs a 802.11 PDU taking the destination and source 
     * hardware addresses.
     * 
     * \param dst_addr The destination hardware address.
     * \param target_addr The source hardware address.
     */
    Dot11BlockAck(const address_type& dst_addr = address_type(), 
                  const address_type& target_addr = address_type());

    /**
     * \brief Constructs a Dot11BlockAck frame object from a buffer 
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
    Dot11BlockAck(const uint8_t* buffer, uint32_t total_sz);

    /* Getters */

    /**
     * \brief Getter for the bar control field.
     * \return The stored bar control field.
     */
    small_uint<4> bar_control() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return bar_control_ & 0xf; 
        #else
        return (bar_control_ >> 8) & 0xf; 
        #endif
    }

    /**
     * \brief Getter for the start sequence field.
     * \return The stored start sequence.
     */
    small_uint<12> start_sequence() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return (start_sequence_ >> 4) & 0xfff; 
        #else
        return (Endian::le_to_host<uint16_t>(start_sequence_) >> 4) & 0xfff; 
        #endif
    }
    
    /**
     * \brief Getter for the fragment number field.
     * \return The stored fragment number field.
     */
    small_uint<4> fragment_number() const { 
        #if TINS_IS_LITTLE_ENDIAN
        return start_sequence_ & 0xf; 
        #else
        return (start_sequence_ >> 8) & 0xf; 
        #endif
    }
    
    /**
     * \brief Returns the 802.11 frame's header length.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size()
     */
    uint32_t header_size() const;

    /* Setters */

    /**
     * \brief Setter for the bar control field.
     * \param bar The bar control field to be set.
     */
    void bar_control(small_uint<4> bar);

    /**
     * \brief Setter for the start sequence field.
     * \param bar The start sequence field to be set.
     */
    void start_sequence(small_uint<12> seq);
    
    /**
     * \brief Setter for the fragment number field.
     * \param frag The fragment number field to be set.
     */
    void fragment_number(small_uint<4> frag);

    /**
     * \brief Getter for the bitmap field.
     * 
     * The returned pointer <b>must not</b> be free'd.
     * 
     * \return The bitmap field.
     */
    const uint8_t* bitmap() const {
        return bitmap_;
    }

    /**
     * \brief Setter for the bitmap field.
     * \param bit The new bitmap field to be set.
     */
    void bitmap(const uint8_t* bit);

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Check whether this PDU matches the specified flag.
     * \param flag The flag to match
     * \sa PDU::matches_flag
     */
    bool matches_flag(PDUType flag) const {
        return flag == pdu_flag || Dot11Control::matches_flag(flag);
    }

    /**
     * \brief Clones this PDU.
     *
     * \sa PDU::clone
     */
    Dot11BlockAck* clone() const {
        return new Dot11BlockAck(*this);
    }
private:
    void write_ext_header(Memory::OutputMemoryStream& stream);

    uint16_t bar_control_, start_sequence_;
    uint8_t bitmap_[bitmap_size];
};

} // namespace Tins

#endif // TINS_DOT11_DOT11_CONTROL_H
