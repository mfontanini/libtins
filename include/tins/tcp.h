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

#ifndef TINS_TCP_H
#define TINS_TCP_H

#include <vector>
#include <stdint.h>
#include <utility>
#include <tins/pdu.h>
#include <tins/macros.h>
#include <tins/endianness.h>
#include <tins/small_uint.h>
#include <tins/pdu_option.h>
#include <tins/cxxstd.h>

namespace Tins {
namespace Memory {
class OutputMemoryStream;
} // Memory

/**
 * \class TCP
 * \brief Represents a TCP PDU.
 *
 * This class represents a TCP PDU. 
 *
 * When sending TCP PDUs, the checksum is calculated automatically
 * every time you send the packet.
 * 
 * While sniffing, the payload sent in each packet will be wrapped
 * in a RawPDU, which is set as the TCP object's inner_pdu. Therefore,
 * if you are sniffing and want to see the TCP packet's payload,
 * you need to do the following:
 *
 * \code
 * // Get a packet from somewhere.
 * TCP tcp = ...;
 *
 * // Extract the RawPDU object.
 * const RawPDU& raw = tcp.rfind_pdu<RawPDU>();
 *
 * // Finally, take the payload (this is a vector<uint8_t>)
 * const RawPDU::payload_type& payload = raw.payload();
 * \endcode
 *
 * \sa RawPDU
 */

class TINS_API TCP : public PDU {
public:
    /**
     * This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::TCP;

    /**
     * \brief TCP flags enum.
     *
     * These flags identify those supported by the TCP PDU.
     */
    enum Flags {
        FIN = 1,
        SYN = 2,
        RST = 4,
        PSH = 8,
        ACK = 16,
        URG = 32,
        ECE = 64,
        CWR = 128
    };

    /**
     * \brief TCP options enum.
     *
     * This enum defines option types supported by TCP PDU.
     */
    enum OptionTypes {
        EOL     = 0,
        NOP     = 1,
        MSS     = 2,
        WSCALE  = 3,
        SACK_OK = 4,
        SACK    = 5,
        TSOPT   = 8,
        ALTCHK  = 14,
        RFC_EXPERIMENT_1 = 253,
        RFC_EXPERIMENT_2 = 254
    };
    
    /**
     * \brief Alternate checksum enum.
     */
    enum AltChecksums {
        CHK_TCP,
        CHK_8FLETCHER,
        CHK_16FLETCHER
    };
    
    /**
     * The type used to store TCP options.
     */
    typedef PDUOption<uint8_t, TCP> option;

    /**
     * The type used to store the options.
     */
    typedef std::vector<option> options_type;
    
    /**
     * The type used to store the sack option.
     */
    typedef std::vector<uint32_t> sack_type;

    /**
     * \brief Extracts metadata for this protocol based on the buffer provided
     *
     * \param buffer Pointer to a buffer
     * \param total_sz Size of the buffer pointed by buffer
     */
    static metadata extract_metadata(const uint8_t *buffer, uint32_t total_sz);

    /**
     * \brief TCP constructor.
     *
     * Creates an instance of TCP. Destination and source port can
     * be provided, otherwise both will be 0.
     * 
     * \param dport Destination port.
     * \param sport Source port.
     * */
    TCP(uint16_t dport = 0, uint16_t sport = 0);

    /**
     * \brief Constructs TCP object from a buffer.
     * 
     * If there is not enough size for a TCP header, or any of the
     * TLV options are malformed, a malformed_packet exception is 
     * thrown.
     * 
     * Any extra data will be stored in a RawPDU.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    TCP(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the destination port field.
     *
     * \return The destination port field value.
     */
    uint16_t dport() const {
        return Endian::be_to_host(header_.dport);
    }

    /**
     * \brief Getter for the source port field.
     *
     * \return The source port field value.
     */
    uint16_t sport() const {
        return Endian::be_to_host(header_.sport);
    }

    /**
     * \brief Getter for the sequence number field.
     *
     * \return The sequence number field value.
     */
    uint32_t seq() const {
        return Endian::be_to_host(header_.seq);
    }

    /**
     * \brief Getter for the acknowledge number field.
     *
     * \return The acknowledge number field value.
     */
    uint32_t ack_seq() const {
        return Endian::be_to_host(header_.ack_seq);
    }

    /**
     * \brief Getter for the window size field.
     *
     * \return The window size field value.
     */
    uint16_t window() const {
        return Endian::be_to_host(header_.window);
    }

    /**
     * \brief Getter for the checksum field.
     *
     * \return The checksum field value.
     */
    uint16_t checksum() const {
        return Endian::be_to_host(header_.check);
    }

    /**
     * \brief Getter for the urgent pointer field.
     *
     * \return The urgent pointer field value.
     */
    uint16_t urg_ptr() const {
        return Endian::be_to_host(header_.urg_ptr);
    }

    /**
     * \brief Getter for the data offset field.
     *
     * \return The data offset field value.
     */
    small_uint<4> data_offset() const {
        return this->header_.doff;
    }

    /**
     * \brief Getter for the option list.
     * 
     * \return The options list.
     */
    const options_type& options() const {
        return options_;
    }

    /**
     * \brief Gets the value of a flag.
     *
     * This method gets the value of a specific flag. If you 
     * want to check for multiple flags at the same time,
     * use TCP::flags.
     *
     * If you want to check if this PDU has the SYN flag on,
     * you can do it like this:
     *
     * \code
     * // Get a TCP packet from somewhere.
     * TCP tcp = ...;
     *
     * if(tcp.get_flag(TCP::SYN)) {
     *     // The SYN flag is on!
     * }
     * \endcode
     * 
     * \sa TCP::flags
     * \param tcp_flag The polled flag.
     * \return The value of the flag.
     */
    small_uint<1> get_flag(Flags tcp_flag) const;

    /**
     * 
     * \brief Gets the flags' values.
     *
     * All of the set flags will be joined together into
     * a 12 bit value. This way, you can check for multiple
     * flags at the same time:
     * 
     * \code
     * TCP tcp = ...;
     * if(tcp.flags() == (TCP::SYN | TCP::ACK)) {
     *     // It's a SYN+ACK!
     * }
     * \endcode
     * 
     * \return The value of the flags field.
     */
    small_uint<12> flags() const;
    
    /* Setters */

    /**
     * \brief Setter for the destination port field.
     *
     * \param new_dport The new destination port.
     */
    void dport(uint16_t new_dport);

    /**
     * \brief Setter for the source port field.
     *
     * \param new_sport The new source port.
     */
    void sport(uint16_t new_sport);

    /**
     * \brief Setter for the sequence number.
     *
     * \param new_seq The new sequence number.
     */
    void seq(uint32_t new_seq);

    /**
     * \brief Setter for the acknowledge number.
     *
     * \param new_ack_seq The new acknowledge number.
     */
    void ack_seq(uint32_t new_ack_seq);

    /**
     * \brief Setter for the window size.
     *
     * \param new_window The new window size.
     */
    void window(uint16_t new_window);

    /**
     * \brief Setter for the urgent pointer field.
     *
     * \param new_urg_ptr The new urgent pointer.
     */
    void urg_ptr(uint16_t new_urg_ptr);

    /**
     * \brief Setter for the data offset pointer field.
     *
     * \param new_doff The new data offset pointer.
     */
    void data_offset(small_uint<4> new_doff);

    // Options

    /**
     * \brief Add a maximum segment size option.
     *
     * \param value The new maximum segment size.
     */
    void mss(uint16_t value);

    /**
     * \brief Searchs for a maximum segment size option.
     * \param value A pointer in which the option's value will be stored.
     * \return True if the option was found, false otherwise.
     */
    uint16_t mss() const;

    /**
     * \brief Add a window scale option.
     *
     * \param value The new window scale.
     */
    void winscale(uint8_t value);
    
    /**
     * \brief Searchs for a window scale option.
     * \param value A pointer in which the option's value will be stored.
     * \return True if the option was found, false otherwise.
     */
    uint8_t winscale() const;

    /**
     * \brief Add a sack permitted option.
     */
    void sack_permitted();
    
    /**
     * \brief Searchs for a sack permitted option.
     * \return True if the option was found, false otherwise.
     */
    bool has_sack_permitted() const;
    
    /**
     * \brief Add a sack option.
     *
     * \param value The new window scale.
     */
    void sack(const sack_type& edges);
    
    /**
     * \brief Searchs for a sack option.
     * \param value A pointer in which the option's value will be stored.
     * \return True if the option was found, false otherwise.
     */
    sack_type sack() const;

    /**
     * \brief Add a timestamp option.
     *
     * \param value The current value of the timestamp clock.
     * \param reply The echo reply field.
     */
    void timestamp(uint32_t value, uint32_t reply);

    /**
     * \brief Searchs for a timestamp option.
     * \param value A pointer in which the option's value will be stored.
     * \param reply A pointer in which the option's reply value will be stored.
     * \return True if the option was found, false otherwise.
     */
    std::pair<uint32_t, uint32_t> timestamp() const;

    /**
     * \brief Add a alternate checksum option.
     *
     * \param value The new alternate checksum scale.
     */
    void altchecksum(AltChecksums value);
    
    /**
     * \brief Searchs for a alternate checksum option.
     * \param value A pointer in which the option's value will be stored.
     * \return True if the option was found, false otherwise.
     */
    AltChecksums altchecksum() const;

    /**
     * \brief Set a TCP flag value.
     *
     * \param tcp_flag The flag to be set.
     * \param value The new value for this flag. Must be 0 or 1.
     */
    void set_flag(Flags tcp_flag, small_uint<1> value);
    
    /**
     * \brief Sets the value of the flag fields.
     *
     * This method can be used to set several flags at the 
     * same time.
     * 
     * \code
     * // Get a TCP packet from somewhere and set the flags to SYN && ACK
     * TCP tcp = ...;
     * tcp.flags(TCP::SYN | TCP::ACK);
     * 
     * // Now also set the PSH flag, without modifying 
     * // the rest of the flags.
     * tcp.flags(tcp.flags() | TCP::PSH);
     * \endcode
     * 
     * \param value The new value of the flags.
     */
    void flags(small_uint<12> value);
    

    /**
     * \brief Adds a TCP option.
     *
     * \param option The option to be added.
     */
    void add_option(const option& opt);
    
    #if TINS_IS_CXX11
        /**
         * \brief Adds a TCP option.
         *
         * This move-constructs the option.
         * 
         * \param option The option to be added.
         */
        void add_option(option &&opt) {
            options_.push_back(std::move(opt));
        }

        /**
         * \brief Adds a TCP option using the provided arguments.
         *
         * The option is constructed from the provided parameters.
         * 
         * \param args The arguments to be used in the option's 
         * constructor.
         */
        template <typename... Args>
        void add_option(Args&&... args) {
            options_.emplace_back(std::forward<Args>(args)...);
        }
    #endif

    /**
     * \brief Removes a TCP option.
     * 
     * If there are multiple options of the given type, only the first one
     * will be removed.
     *
     * \param type The type of the option to be removed.
     * \return true if the option was removed, false otherwise.
     */
    bool remove_option(OptionTypes type);

    /**
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. This size includes the
     * payload and options size.
     *
     * \sa PDU::header_size
     */
    uint32_t header_size() const;
    
    /**
     * \brief Check whether ptr points to a valid response for this PDU.
     *
     * \sa PDU::matches_response
     * \param ptr The pointer to the buffer.
     * \param total_sz The size of the buffer.
     */
    bool matches_response(const uint8_t* ptr, uint32_t total_sz) const;

    /**
     * \brief Getter for the PDU's type.
     *
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }

    /**
     * \brief Searchs for an option that matchs the given type.
     * \param type The option type to be searched.
     * \return A pointer to the option, or 0 if it was not found.
     */
    const option* search_option(OptionTypes type) const;
    
    /**
     * \sa PDU::clone
     */
    TCP* clone() const {
        return new TCP(*this);
    }
private:
    #if TINS_IS_LITTLE_ENDIAN
        TINS_BEGIN_PACK
        struct flags_type {
            uint8_t fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
        } TINS_END_PACK;
    #else
        TINS_BEGIN_PACK
        struct flags_type {
            uint8_t cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
        } TINS_END_PACK;
    #endif

    TINS_BEGIN_PACK
    struct tcp_header {
        uint16_t sport;
        uint16_t dport;
        uint32_t seq;
        uint32_t ack_seq;
    #if TINS_IS_LITTLE_ENDIAN
        uint8_t res1:4,
            doff:4;
    #else
        uint8_t doff:4,
            res1:4;
    #endif
        union {
            flags_type flags;
            uint8_t flags_8;
        };
        uint16_t	window;
        uint16_t	check;
        uint16_t	urg_ptr;
    } TINS_END_PACK;

    static const uint16_t DEFAULT_WINDOW;
    
    template <typename T> 
    T generic_search(OptionTypes opt_type) const {
        const option* opt = search_option(opt_type);
        if (!opt) {
            throw option_not_found();
        }
        return opt->to<T>();
    }
    
    void write_serialization(uint8_t* buffer, uint32_t total_sz);
    void checksum(uint16_t new_check);
    uint32_t calculate_options_size() const;
    uint32_t pad_options_size(uint32_t size) const;
    options_type::const_iterator search_option_iterator(OptionTypes type) const;
    options_type::iterator search_option_iterator(OptionTypes type);
    
    void write_option(const option& opt, Memory::OutputMemoryStream& stream);

    options_type options_;
    tcp_header header_;
};

} // Tins

#endif // TINS_TCP_H
