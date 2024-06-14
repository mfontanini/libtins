#include <gtest/gtest.h>
#include <string>
#include <tins/endianness.h>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/udp.h>
#include <tins/pdu.h>
#include <tins/rawpdu.h>
#include <tins/small_uint.h>
#include <tins/bfd.h>

#define PACKET_SIZE 52ul
#define DEFAULT_HEADER_SIZE 24ul

using namespace std;
using namespace Tins;

class BFDTest : public testing::Test {
public:
    static const uint8_t expected_packet[PACKET_SIZE];
    static const small_uint<3> version;
    static const BFD::Diagnostic diagnostic;
    static const BFD::State state;
    static const uint8_t detect_mult;
    static const uint32_t my_discriminator, your_discriminator;
    static const uint32_t desired_min_tx_interval, required_min_rx_interval, required_min_echo_rx_interval;
    static const BFD::AuthenticationType auth_type;
    static const uint8_t sha1_auth_len, auth_key_id;
    static const uint32_t auth_seq_num;
    static const byte_array auth_sha1_value;
    static const byte_array password1, password2;
    static const uint16_t dport, sport;
    static const IP::address_type dst_ip, src_ip;
    static const EthernetII::address_type dst_addr, src_addr;
};

const uint8_t BFDTest::expected_packet[PACKET_SIZE] = {
    0x20, 0xff, 0x05, 0x34,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xff,
    0x00, 0x00, 0x00, 0xff,
    0x00, 0x00, 0x00, 0x0c,
    0x05, 0x1c, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x3d, 0xde, 0x2a, 0x34,
    0xef, 0x6c, 0xaf, 0xf9,
    0xa4, 0x05, 0x87, 0xab,
    0x41, 0x23, 0x87, 0x53,
    0x21, 0xcd, 0x99, 0xce,
};

const small_uint<3> BFDTest::version = 1;
const BFD::Diagnostic BFDTest::diagnostic = BFD::Diagnostic::NO_DIAGNOSTIC;
const BFD::State BFDTest::state = BFD::State::UP;
const uint8_t BFDTest::detect_mult = 5;
const uint32_t BFDTest::my_discriminator = 1;
const uint32_t BFDTest::your_discriminator = 0;
const uint32_t BFDTest::desired_min_tx_interval = 0xff;
const uint32_t BFDTest::required_min_rx_interval = 0xff;
const uint32_t BFDTest::required_min_echo_rx_interval = 0x0c;
const BFD::AuthenticationType BFDTest::auth_type = BFD::AuthenticationType::METICULOUS_KEYED_SHA1;
const uint8_t BFDTest::sha1_auth_len = 28;
const uint8_t BFDTest::auth_key_id = 1;
const uint32_t BFDTest::auth_seq_num = 1;
const byte_array BFDTest::auth_sha1_value = {0x3d, 0xde, 0x2a, 0x34, 0xef, 0x6c, 0xaf, 0xf9, 0xa4, 0x05, 0x87, 0xab, 0x41, 0x23, 0x87, 0x53, 0x21, 0xcd, 0x99, 0xce};
const byte_array BFDTest::password1 = {0x41, 0x42, 0x43, 0x44, 0x45};
const byte_array BFDTest::password2 = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c};
const uint16_t BFDTest::dport = 3784;
const uint16_t BFDTest::sport = 49152;
const IP::address_type BFDTest::dst_ip = IP::address_type{"2.2.2.2"};
const IP::address_type BFDTest::src_ip = IP::address_type{"1.1.1.1"};
const EthernetII::address_type BFDTest::dst_addr = EthernetII::address_type{"aa:bb:cc:dd:ee:ff"};
const EthernetII::address_type BFDTest::src_addr = EthernetII::address_type{"8a:8b:8c:8d:8e:8f"};

TEST_F(BFDTest, DefaultConstructor) {
    auto const bfd = BFD{};
    EXPECT_EQ(bfd.version(), version);
    EXPECT_EQ(bfd.diagnostic(), BFD::Diagnostic::NO_DIAGNOSTIC);
    EXPECT_EQ(bfd.state(), BFD::State::ADMIN_DOWN);
    EXPECT_EQ(bfd.poll(), false);
    EXPECT_EQ(bfd.final(), false);
    EXPECT_EQ(bfd.control_plane_independent(), false);
    EXPECT_EQ(bfd.authentication_present(), false);
    EXPECT_EQ(bfd.demand(), false);
    EXPECT_EQ(bfd.multipoint(), false);
    EXPECT_EQ(bfd.detect_mult(), 0);
    EXPECT_EQ(bfd.length(), DEFAULT_HEADER_SIZE);
    EXPECT_EQ(bfd.my_discriminator(), (unsigned int)0);
    EXPECT_EQ(bfd.your_discriminator(), (unsigned int)0);
    EXPECT_EQ(bfd.desired_min_tx_interval(), (unsigned int)0);
    EXPECT_EQ(bfd.required_min_rx_interval(), (unsigned int)0);
    EXPECT_EQ(bfd.required_min_echo_rx_interval(), (unsigned int)0);
    EXPECT_EQ(bfd.auth_type(), BFD::AuthenticationType::RESERVED);
    EXPECT_EQ(bfd.auth_len(), 0);
    EXPECT_EQ(bfd.auth_key_id(), 0);
}

TEST_F(BFDTest, Serialize) {
    auto bfd = BFD{};
    bfd.version(version);
    bfd.diagnostic(diagnostic);
    bfd.state(state);
    bfd.poll(true);
    bfd.final(true);
    bfd.control_plane_independent(true);
    bfd.authentication_present(true);
    bfd.demand(true);
    bfd.multipoint(true);
    bfd.detect_mult(detect_mult);
    bfd.length(PACKET_SIZE);
    bfd.my_discriminator(my_discriminator);
    bfd.your_discriminator(your_discriminator);
    bfd.desired_min_tx_interval(desired_min_tx_interval);
    bfd.required_min_rx_interval(required_min_rx_interval);
    bfd.required_min_echo_rx_interval(required_min_echo_rx_interval);
    bfd.auth_type(auth_type);
    bfd.auth_len(sha1_auth_len);
    bfd.auth_key_id(auth_key_id);
    bfd.auth_sequence_number(auth_seq_num);
    bfd.auth_sha1_value(auth_sha1_value);

    auto const serialized = bfd.serialize();
    EXPECT_EQ(serialized.size(), PACKET_SIZE);
    EXPECT_TRUE(equal(serialized.begin(), serialized.end(), expected_packet));
}

TEST_F(BFDTest, ConstructorFromBuffer) {
    auto const bfd = BFD{expected_packet, PACKET_SIZE};
    EXPECT_EQ(bfd.version(), version);
    EXPECT_EQ(bfd.diagnostic(), diagnostic);
    EXPECT_EQ(bfd.state(), state);
    EXPECT_EQ(bfd.poll(), true);
    EXPECT_EQ(bfd.final(), true);
    EXPECT_EQ(bfd.control_plane_independent(), true);
    EXPECT_EQ(bfd.authentication_present(), true);
    EXPECT_EQ(bfd.demand(), true);
    EXPECT_EQ(bfd.multipoint(), true);
    EXPECT_EQ(bfd.detect_mult(), detect_mult);
    EXPECT_EQ(bfd.length(), PACKET_SIZE);
    EXPECT_EQ(bfd.my_discriminator(), my_discriminator);
    EXPECT_EQ(bfd.your_discriminator(), your_discriminator);
    EXPECT_EQ(bfd.desired_min_tx_interval(), desired_min_tx_interval);
    EXPECT_EQ(bfd.required_min_rx_interval(), required_min_rx_interval);
    EXPECT_EQ(bfd.required_min_echo_rx_interval(), required_min_echo_rx_interval);
    EXPECT_EQ(bfd.auth_type(), auth_type);
    EXPECT_EQ(bfd.auth_len(), sha1_auth_len);
    EXPECT_EQ(bfd.auth_key_id(), auth_key_id);
    EXPECT_EQ(bfd.auth_sequence_number(), auth_seq_num);
    EXPECT_EQ(bfd.auth_sha1_value(), auth_sha1_value);
}

TEST_F(BFDTest, ChangePassword) {
    auto bfd = BFD{};
    EXPECT_THROW(bfd.password(byte_array{}), logic_error);

    bfd.auth_type(BFD::AuthenticationType::SIMPLE_PASSWORD);

    bfd.password(password1);
    auto const set_password1 = bfd.password();
    EXPECT_EQ(set_password1, password1);

    bfd.password(password2);
    auto const set_password2 = bfd.password();
    EXPECT_EQ(set_password2, password2);

    EXPECT_THROW(bfd.password(byte_array{}), invalid_argument);

    EXPECT_THROW(bfd.password(byte_array(BFD::MAX_PASSWORD_SIZE + 1, 0x41)), invalid_argument);
}

TEST_F(BFDTest, InvalidAuthValue) {
    auto bfd = BFD{};

    bfd.auth_type(BFD::AuthenticationType::KEYED_MD5);
    EXPECT_THROW(bfd.auth_md5_value(byte_array{}), invalid_argument);

    bfd.auth_type(BFD::AuthenticationType::METICULOUS_KEYED_MD5);
    EXPECT_THROW(bfd.auth_md5_value(byte_array{}), invalid_argument);

    bfd.auth_type(BFD::AuthenticationType::KEYED_SHA1);
    EXPECT_THROW(bfd.auth_sha1_value(byte_array{}), invalid_argument);

    bfd.auth_type(BFD::AuthenticationType::METICULOUS_KEYED_SHA1);
    EXPECT_THROW(bfd.auth_sha1_value(byte_array{}), invalid_argument);
}

TEST_F(BFDTest, OuterUDP) {
    auto pkt = EthernetII{dst_addr, src_addr} / IP{dst_ip, src_ip} / UDP{dport, sport} / BFD{expected_packet, PACKET_SIZE};

    auto udp = pkt.find_pdu<UDP>();
    ASSERT_TRUE(udp != nullptr);
    EXPECT_EQ(udp->dport(), dport);
    EXPECT_EQ(udp->sport(), sport);

    auto bfd = udp->find_pdu<BFD>();
    ASSERT_TRUE(bfd != nullptr);
    EXPECT_EQ(bfd->header_size(), PACKET_SIZE);
    EXPECT_EQ(bfd->size(), PACKET_SIZE);
}
