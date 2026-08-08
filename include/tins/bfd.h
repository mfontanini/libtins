#ifndef TINS_BFD_H
#define TINS_BFD_H

#include <tins/endianness.h>
#include <tins/pdu.h>
#include <tins/pdu_option.h>
#include <tins/small_uint.h>

namespace Tins {

/**
 * \class BFD
 * \brief Represents a BFD PDU.
 *
 * This class represents a BFD PDU.
 *
 * \sa RawPDU
 */
class TINS_API BFD : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::BFD;

    /**
     * Constants used by the BFD PDU class.
     */
    static const size_t MAX_PASSWORD_SIZE = 16;
    static const uint8_t MD5_DIGEST_SIZE = 16;
    static const uint8_t SHA1_HASH_SIZE = 20;

    /**
     * BFD Diagnostic Codes from RFC 5880 (and RFC 6428 for code 0x09).
     * Diag values from 0x0A to 0x1F are unassigned and reserved for future use.
     */
    enum Diagnostic {
        NO_DIAGNOSTIC = 0x00,
        CONTROL_DETECTION_TIME_EXPIRED = 0x01,
        ECHO_FUNCTION_FAILED = 0x02,
        NEIGHBOR_SIGNALED_SESSION_DOWN = 0x03,
        FORWARDING_PLANE_RESET = 0x04,
        PATH_DOWN = 0x05,
        CONCATENATED_PATH_DOWN = 0x06,
        ADMINISTRATIVELY_DOWN = 0x07,
        REVERSE_CONCATENATED_PATH_DOWN = 0x08,
        MISCONNECTIVITY_DEFECT = 0x09,
    };

    /**
     * BFD State.
     */
    enum State {
        ADMIN_DOWN = 0x00,
        DOWN = 0x01,
        INIT = 0x02,
        UP = 0x03,
    };

    /**
     * BFD Authentication Types.
     * Auth type values from 0x06 to 0xFF are unassigned and reserved for future use.
     */
    enum AuthenticationType {
        RESERVED = 0x00,
        SIMPLE_PASSWORD = 0x01,
        KEYED_MD5 = 0x02,
        METICULOUS_KEYED_MD5 = 0x03,
        KEYED_SHA1 = 0x04,
        METICULOUS_KEYED_SHA1 = 0x05,
    };

    /**
     * Default constructor.
     */
    BFD();

    /**
     * \brief Constructs a BFD object from a buffer.
     *
     * \param data The buffer from which this PDU will be constructed.
     * \param size The size of the data buffer.
     */
    BFD(const uint8_t* data, uint32_t size);

    /**
     * \brief Getter for the version.
     */
    small_uint<3> version() const { return header_.version; }

    /**
     * \brief Getter for the diagnostic code.
     */
    enum Diagnostic diagnostic() const { return static_cast<Diagnostic>(header_.diagnostic); }

    /**
     * \brief Getter for the state.
     */
    enum State state() const { return static_cast<State>(header_.state); }

    /**
     * \brief Getter for the poll bit.
     */
    bool poll() const { return header_.poll; }

    /**
     * \brief Getter for the final bit.
     */
    bool final() const { return header_.final; }

    /**
     * \brief Getter for the control plane independent bit.
     */
    bool control_plane_independent() const { return header_.control_plane_independent; }

    /**
     * \brief Getter for the authentication present bit.
     */
    bool authentication_present() const { return header_.authentication_present; }

    /**
     * \brief Getter for the demand bit.
     */
    bool demand() const { return header_.demand; }

    /**
     * \brief Getter for the multipoint bit.
     */
    bool multipoint() const { return header_.multipoint; }

    /**
     * \brief Getter for the detection time multiplier.
     */
    uint8_t detect_mult() const { return header_.detect_mult; }

    /**
     * \brief Getter for the length.
     */
    uint8_t length() const { return header_.length; }

    /**
     * \brief Getter for the local discriminator ID.
     */
    uint32_t my_discriminator() const { return Endian::be_to_host(header_.my_discriminator); }

    /**
     * \brief Getter for the remote discriminator ID.
     */
    uint32_t your_discriminator() const { return Endian::be_to_host(header_.your_discriminator); }

    /**
     * \brief Getter for the minimum interval that the local system would like to use when transmitting BFD control packets.
     */
    uint32_t desired_min_tx_interval() const { return Endian::be_to_host(header_.desired_min_tx_interval); }

    /**
     * \brief Getter for the minimum interval between received BFD control packets.
     */
    uint32_t required_min_rx_interval() const { return Endian::be_to_host(header_.required_min_rx_interval); }

    /**
     * \brief Getter for the minimum interval between received BFD echo packets.
     */
    uint32_t required_min_echo_rx_interval() const { return Endian::be_to_host(header_.required_min_echo_rx_interval); }

    /**
     * \brief Getter for the authentication type.
     */
    enum AuthenticationType auth_type() const { return static_cast<AuthenticationType>(auth_header_.auth_type); }

    /**
     * \brief Getter for the authentication length.
     */
    uint8_t auth_len() const { return auth_header_.auth_len; }

    /**
     * \brief Getter for the authentication key ID.
     */
    uint8_t auth_key_id() const { return auth_header_.auth_key_id; }

    /**
     * \brief Getter for the password.
     */
    const byte_array& password() const;

    /**
     * \brief Getter for the authentication sequence number.
     */
    uint32_t auth_sequence_number() const;

    /**
     * \brief Getter for the MD5 authentication value.
     */
    const byte_array auth_md5_value() const;

    /**
     * \brief Getter for the SHA1 authentication value.
     */
    const byte_array auth_sha1_value() const;

    /**
     * \brief Setter for the version.
     * \param version The new version.
     */
    void version(small_uint<3> version) { header_.version = version; }

    /**
     * \brief Setter for the diagnostic code.
     * \param diagnostic The new diagnostic code.
     */
    void diagnostic(enum Diagnostic diagnostic) { header_.diagnostic = static_cast<small_uint<5>>(diagnostic); }

    /**
     * \brief Setter for the state.
     * \param state The new state.
     */
    void state(enum State state) { header_.state = static_cast<small_uint<2>>(state); }

    /**
     * \brief Setter for the poll bit.
     * \param poll The new poll bit.
     */
    void poll(bool poll) { header_.poll = poll; }

    /**
     * \brief Setter for the final bit.
     * \param final The new final bit.
     */
    void final(bool final) { header_.final = final; }

    /**
     * \brief Setter for the control plane independent bit.
     * \param control_plane_independent The new control plane independent bit.
     */
    void control_plane_independent(bool control_plane_independent) { header_.control_plane_independent = control_plane_independent; }

    /**
     * \brief Setter for the authentication present bit.
     * \param authentication_present The new authentication present bit.
     */
    void authentication_present(bool authentication_present) { header_.authentication_present = authentication_present; }

    /**
     * \brief Setter for the demand bit.
     * \param demand The new demand bit.
     */
    void demand(bool demand) { header_.demand = demand; }

    /**
     * \brief Setter for the multipoint bit.
     * \param multipoint The new multipoint bit.
     */
    void multipoint(bool multipoint) { header_.multipoint = multipoint; }

    /**
     * \brief Setter for the detection time multiplier.
     * \param detect_mult The new detection time multiplier.
     */
    void detect_mult(uint8_t detect_mult) { header_.detect_mult = detect_mult; }

    /**
     * \brief Setter for the length.
     * \param length The new length.
     */
    void length(uint8_t length) { header_.length = length; }

    /**
     * \brief Setter for the local discriminator ID.
     * \param my_discriminator The new local discriminator ID.
     */
    void my_discriminator(uint32_t my_discriminator) { header_.my_discriminator = Endian::host_to_be(my_discriminator); }

    /**
     * \brief Setter for the remote discriminator ID.
     * \param your_discriminator The new remote discriminator ID.
     */
    void your_discriminator(uint32_t your_discriminator) { header_.your_discriminator = Endian::host_to_be(your_discriminator); }

    /**
     * \brief Setter for the minimum interval that the local system would like to use when transmitting BFD control packets.
     * \param desired_min_tx_interval The new desired minimum transmission interval.
     */
    void desired_min_tx_interval(uint32_t desired_min_tx_interval) { header_.desired_min_tx_interval = Endian::host_to_be(desired_min_tx_interval); }

    /**
     * \brief Setter for the minimum interval between received BFD control packets.
     * \param required_min_rx_interval The new required minimum reception interval.
     */
    void required_min_rx_interval(uint32_t required_min_rx_interval) { header_.required_min_rx_interval = Endian::host_to_be(required_min_rx_interval); }

    /**
     * \brief Setter for the minimum interval between received BFD echo packets.
     * \param required_min_echo_rx_interval The new required minimum echo reception interval.
     */
    void required_min_echo_rx_interval(uint32_t required_min_echo_rx_interval) { header_.required_min_echo_rx_interval = Endian::host_to_be(required_min_echo_rx_interval); }

    /**
     * \brief Setter for the authentication type.
     * \param auth_type The new authentication type.
     */
    void auth_type(enum AuthenticationType auth_type) { auth_header_.auth_type = static_cast<uint8_t>(auth_type); }

    /**
     * \brief Setter for the authentication length.
     * \param auth_len The new authentication length.
     */
    void auth_len(uint8_t auth_len) { auth_header_.auth_len = auth_len; }

    /**
     * \brief Setter for the authentication key ID.
     * \param auth_key_id The new authentication key ID.
     */
    void auth_key_id(uint8_t auth_key_id) { auth_header_.auth_key_id = auth_key_id; }

    /**
     * \brief Setter for the password.
     * \param password The new password.
     */
    void password(const byte_array& password);

    /**
     * \brief Clear the password.
     */
    void clear_password() { password_.clear(); }

    /**
     * \brief Setter for the authentication sequence number.
     * \param sequence_number The new authentication sequence number.
     */
    void auth_sequence_number(uint32_t sequence_number);

    /**
     * \brief Setter for the MD5 authentication value.
     * \param auth_value The new MD5 authentication value.
     */
    void auth_md5_value(const byte_array& auth_value);

    /**
     * \brief Setter for the SHA1 authentication value.
     * \param auth_value The new SHA1 authentication value.
     */
    void auth_sha1_value(const byte_array& auth_value);

    /**
     * \brief Returns the BFD frame's header length.
     *
     * This method overrides PDU::header_size.
     *
     * \return An uint32_t with the header's size.
     * \sa PDU::header_size
     */
    uint32_t header_size() const;

    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }

    /**
     * \sa PDU::clone
     */
    BFD *clone() const { return new BFD(*this); }

private:
    TINS_BEGIN_PACK
    struct bfd_header {
        #if TINS_IS_BIG_ENDIAN
            uint16_t version:3,
                     diagnostic:5,
                     state:2,
                     poll:1,
                     final:1,
                     control_plane_independent:1,
                     authentication_present:1,
                     demand:1,
                     multipoint:1;
        #elif TINS_IS_LITTLE_ENDIAN
            uint16_t diagnostic:5,
                     version:3,
                     multipoint:1,
                     demand:1,
                     authentication_present:1,
                     control_plane_independent:1,
                     final:1,
                     poll:1,
                     state:2;
        #endif
        uint8_t detect_mult;
        uint8_t length;
        uint32_t my_discriminator;
        uint32_t your_discriminator;
        uint32_t desired_min_tx_interval;
        uint32_t required_min_rx_interval;
        uint32_t required_min_echo_rx_interval;
    } TINS_END_PACK;

    TINS_BEGIN_PACK
    struct bfd_authentication_header {
        uint8_t auth_type;
        uint8_t auth_len;
        uint8_t auth_key_id;
    } TINS_END_PACK;

    TINS_BEGIN_PACK
    struct bfd_md5_authentication_data {
        uint32_t sequence_number;
        uint8_t auth_value[MD5_DIGEST_SIZE];
    } TINS_END_PACK;

    TINS_BEGIN_PACK
    struct bfd_sha1_authentication_data {
        uint32_t sequence_number;
        uint8_t auth_value[SHA1_HASH_SIZE];
    } TINS_END_PACK;

    void write_serialization(uint8_t* buffer, uint32_t size);

    bfd_header header_;
    bfd_authentication_header auth_header_;
    byte_array password_;
    bfd_md5_authentication_data auth_data_md5_;
    bfd_sha1_authentication_data auth_data_sha1_;
};

} // Tins

#endif // TINS_BFD_H
