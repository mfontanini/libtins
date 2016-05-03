/*
 * Copyright (c) 2016, Matias Fontanini
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

#ifndef TINS_EXCEPTIONS_H
#define TINS_EXCEPTIONS_H

#include <string>
#include <stdexcept>

namespace Tins {

/**
 * \brief Base class for all libtins exceptions.
 */
class exception_base : public std::runtime_error {
public:
    exception_base() 
    : std::runtime_error(std::string()) { }

    exception_base(const std::string& message) 
    : std::runtime_error(message) { }

    exception_base(const char* message) 
    : std::runtime_error(message) { }
};

/**
 * \brief Exception thrown when an option is not found.
 */
class option_not_found : public exception_base {
public:
    option_not_found() : exception_base("Option not found") { }
};

/**
 * \brief Exception thrown when a malformed packet is parsed.
 */
class malformed_packet : public exception_base {
public:
    malformed_packet() : exception_base("Malformed packet") { }
};

/**
 * \brief Exception thrown when serializing a packet fails.
 */
class serialization_error : public exception_base {
public:
    serialization_error() : exception_base("Serialization error") { }
};

/**
 * \brief Exception thrown when a PDU is not found when using PDU::rfind_pdu.
 */
class pdu_not_found : public exception_base {
public:
    pdu_not_found() : exception_base("PDU not found") { }
};

/**
 * \brief Exception thrown when PDU::send requires a valid interface,
 * but an invalid is used.
 */
class invalid_interface : public exception_base {
public:
    invalid_interface() : exception_base("Invalid interface") { }
};

/**
 * \brief Exception thrown when an invalid string representation of an address
 * is provided
 */
class invalid_address : public exception_base {
public:
    invalid_address() : exception_base("Invalid address") { }
};

/**
 * \brief Exception thrown when a field is not present in frame.
 */
class field_not_present : public exception_base {
public:
    field_not_present() : exception_base("Field not present") { }
};

/**
 * \brief Exception thrown when PacketSender fails to open a socket.
 */
class socket_open_error : public exception_base {
public:
    socket_open_error(const std::string& msg)
    : exception_base(msg) { }
};

/**
 * \brief Exception thrown when PacketSender fails to close a socket.
 */
class socket_close_error : exception_base {
public:
    socket_close_error(const std::string& msg)
    : exception_base(msg) { }
};

/**
 * \brief Exception thrown when PacketSender fails to write on a socket.
 */
class socket_write_error : public exception_base {
public:
    socket_write_error(const std::string& msg)
    : exception_base(msg) { }
};

/**
 * \brief Exception thrown when an invalid socket type is provided
 * to PacketSender.
 */
class invalid_socket_type : public exception_base {
public:
    invalid_socket_type() : exception_base("The provided socket type is invalid") { }
};

/**
 * \brief Exception thrown when an unkown link layer PDU type is
 * found while sniffing.
 */
class unknown_link_type : public exception_base {
public:
    unknown_link_type() : exception_base("The sniffed link layer PDU type is unknown") { }
};

/**
 * \brief Exception thrown when a malformed option is found.
 */
class malformed_option : public exception_base {
public:
    malformed_option() : exception_base("Malformed option") { }
};

/**
 * \brief Exception thrown when a call to tins_cast fails.
 */
class bad_tins_cast : public exception_base {
public:
    bad_tins_cast() : exception_base("Bad Tins cast") { }
};

/**
 * \brief Exception thrown when sniffing a protocol that
 * has been disabled at compile time.
 */
class protocol_disabled : public exception_base {
public:
    protocol_disabled() : exception_base("Protocol disabled") { }
};

/**
 * \brief Exception thrown when a feature has been disabled
 * at compile time.
 */
class feature_disabled : public exception_base {
public:
    feature_disabled() : exception_base("Feature disabled") { }
};

/**
 * \brief Exception thrown when a payload is too large to fit
 * into a PDUOption.
 */
class option_payload_too_large : public exception_base {
public:
    option_payload_too_large() : exception_base("Option payload too large") { }
};

/**
 * \brief Generic pcap error
 */
class pcap_error : public exception_base {
public:
    pcap_error(const char* message) : exception_base(message) {

    }
};

/**
 * \brief Exception thrown when an invalid pcap filter is compiled
 */
class invalid_pcap_filter : public exception_base {
public:
    invalid_pcap_filter(const char* message) : exception_base(message) {

    }
};

/**
 * \brief Exception thrown when serialiation of a non-serializable PDU
 * is attempted
 */
class pdu_not_serializable : public exception_base {
public:
    pdu_not_serializable() : exception_base("PDU not serializable") { }
};

/**
 * \brief Exception thrown when opening a pcap handle fails
 */
class pcap_open_failed : public exception_base {
public:
    pcap_open_failed() : exception_base("Failed to create pcap handle") { }
};

/**
 * \brief Exception thrown when a function not supported on the current OS
 * is called
 */
class unsupported_function : public exception_base {
public:
    unsupported_function() : exception_base("Function is not supported on this OS") { }
};

/**
 * \brief Exception thrown when an invalid domain name is parsed
 */
class invalid_domain_name : public exception_base {
public:
    invalid_domain_name() : exception_base("Invalid domain name") { }
};

/**
 * \brief Exception thrown when a stream is not found
 */
class stream_not_found : public exception_base {
public:
    stream_not_found() : exception_base("Stream not found") { }
};

/**
 * \brief Exception thrown when a required callback for an object is not set
 */
class callback_not_set : public exception_base {
public:
    callback_not_set() : exception_base("Callback not set") { }
};

/**
 * \brief Exception thrown when an invalid packet is provided to some function
 */
class invalid_packet : public exception_base {
public:
    invalid_packet() : exception_base("Invalid packet") { }
};

namespace Crypto {
namespace WPA2 {
    /**
     * \brief Exception thrown when an invalid WPA2 handshake is found.
     */
    class invalid_handshake : public exception_base {
    public:
        invalid_handshake() : exception_base("Invalid WPA2 handshake") { }
    };
} // WPA2
} // Crypto

} // Tins

#endif // TINS_EXCEPTIONS_H
