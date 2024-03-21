#include <gtest/gtest.h>
#include <string>
#include <tins/endianness.h>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/udp.h>
#include <tins/pdu.h>
#include <tins/rawpdu.h>
#include <tins/small_uint.h>
#include <tins/rtp.h>

#define PACKET_SIZE 60ul
#define CSRC_COUNT 5
#define EXTENSION_LENGTH 2
#define PAYLOAD_SIZE 12

using namespace std;
using namespace Tins;

class RTPTest : public testing::Test {
public:
    static const uint8_t expected_packet[PACKET_SIZE];
    static const uint8_t invalid_packet_one[];
    static const uint8_t invalid_packet_two[];
    static const uint8_t packet_with_zero_padding_value[];
    static const uint8_t packet_without_data_one[];
    static const uint8_t packet_without_data_two[];
    static const uint8_t packet_with_zero_extension_length[];
    static const small_uint<2> version;
    static const small_uint<1> padding;
    static const small_uint<1> extension;
    static const small_uint<4> csrc_count;
    static const small_uint<1> marker;
    static const small_uint<7> payload_type;
    static const uint16_t sequence_number;
    static const uint32_t timestamp;
    static const uint32_t ssrc_id;
    static const uint32_t csrc_ids[CSRC_COUNT];
    static const uint16_t profile;
    static const uint16_t extension_length;
    static const uint32_t extension_data[EXTENSION_LENGTH];
    static const uint8_t padding_size;
    static const uint8_t payload[PAYLOAD_SIZE];
    static const uint16_t dport, sport;
    static const IP::address_type dst_ip, src_ip;
    static const EthernetII::address_type dst_addr, src_addr;
};

const uint8_t RTPTest::expected_packet[PACKET_SIZE] = {
    0xb5, 0xaa, 0xa4, 0x10,
    0xde, 0xad, 0xbe, 0xef,
    0xab, 0xcd, 0xad, 0xbc,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x05,
    0x01, 0x01, 0x00, 0x02,
    0x77, 0x00, 0x00, 0x00,
    0x88, 0x00, 0x00, 0x00,
    0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42,
    0x00, 0x00, 0x00, 0x04,
};

const uint8_t RTPTest::invalid_packet_one[] = {
    160, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0xff,
};

const uint8_t RTPTest::invalid_packet_two[] = {
    160, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1,
};

const uint8_t RTPTest::packet_with_zero_padding_value[] = {
    160, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
};

const uint8_t RTPTest::packet_without_data_one[] = {
    128, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1,
};

const uint8_t RTPTest::packet_without_data_two[] = {
    160, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7,
};

const uint8_t RTPTest::packet_with_zero_extension_length[] = {
    144, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0x56, 0x97, 0, 0,
};

const small_uint<2> RTPTest::version = 2;
const small_uint<1> RTPTest::padding = 1;
const small_uint<1> RTPTest::extension = 1;
const small_uint<4> RTPTest::csrc_count = CSRC_COUNT;
const small_uint<1> RTPTest::marker = 1;
const small_uint<7> RTPTest::payload_type = 42;
const uint16_t RTPTest::sequence_number = 42000;
const uint32_t RTPTest::timestamp = 0xdeadbeef;
const uint32_t RTPTest::ssrc_id = 0xabcdadbc;
const uint32_t RTPTest::csrc_ids[CSRC_COUNT] = { 1, 2, 3, 4, 5 };
const uint16_t RTPTest::profile = 0x0101;
const uint16_t RTPTest::extension_length = EXTENSION_LENGTH;
const uint32_t RTPTest::extension_data[EXTENSION_LENGTH] = { 0x77000000, 0x88000000 };
const uint8_t RTPTest::padding_size = 4;
const uint8_t RTPTest::payload[PAYLOAD_SIZE] = {
    0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42,
};
const uint16_t RTPTest::dport = 5004;
const uint16_t RTPTest::sport = 30000;
const IP::address_type RTPTest::dst_ip = IP::address_type{"2.2.2.2"};
const IP::address_type RTPTest::src_ip = IP::address_type{"1.1.1.1"};
const EthernetII::address_type RTPTest::dst_addr = EthernetII::address_type{"aa:bb:cc:dd:ee:ff"};
const EthernetII::address_type RTPTest::src_addr = EthernetII::address_type{"8a:8b:8c:8d:8e:8f"};

TEST_F(RTPTest, DefaultConstructor) {
    auto const rtp = RTP{};
    EXPECT_EQ(rtp.version(), version);
    EXPECT_EQ(rtp.padding_bit(), 0);
    EXPECT_EQ(rtp.extension_bit(), 0);
    EXPECT_EQ(rtp.csrc_count(), 0);
    EXPECT_EQ(rtp.marker_bit(), 0);
    EXPECT_EQ(rtp.payload_type(), 0);
    EXPECT_EQ(rtp.sequence_number(), 0);
    EXPECT_EQ(rtp.timestamp(), 0);
    EXPECT_EQ(rtp.ssrc_id(), 0);
    EXPECT_EQ(rtp.csrc_ids().size(), 0);
    EXPECT_EQ(rtp.extension_profile(), 0);
    EXPECT_EQ(rtp.extension_length(), 0);
    EXPECT_EQ(rtp.extension_data().size(), 0);
    EXPECT_EQ(rtp.padding_size(), 0);
    EXPECT_EQ(rtp.header_size(), 12);
    EXPECT_EQ(rtp.trailer_size(), 0);
}

TEST_F(RTPTest, Serialize) {
    auto rtp = RTP{};
    rtp.version(version);
    rtp.padding_size(padding_size);
    rtp.extension_bit(extension);
    rtp.marker_bit(marker);
    rtp.payload_type(payload_type);
    rtp.sequence_number(sequence_number);
    rtp.timestamp(timestamp);
    rtp.ssrc_id(ssrc_id);

    for (auto csrc_id : csrc_ids) {
        rtp.add_csrc_id(csrc_id);
    }

    rtp.extension_profile(profile);

    for (auto data : extension_data) {
        rtp.add_extension_data(data);
    }

    auto raw_pdu = RawPDU(payload, PAYLOAD_SIZE);
    rtp.inner_pdu(raw_pdu);

    EXPECT_EQ(rtp.header_size(), PACKET_SIZE - PAYLOAD_SIZE - padding_size);
    EXPECT_EQ(rtp.trailer_size(), padding_size);

    auto serialized = rtp.serialize();
    ASSERT_EQ(serialized.size(), PACKET_SIZE);
    EXPECT_TRUE(std::equal(serialized.begin(), serialized.end(), expected_packet));
}

TEST_F(RTPTest, ConstructorFromBuffer) {
    auto rtp = RTP{expected_packet, PACKET_SIZE};
    EXPECT_EQ(rtp.version(), version);
    EXPECT_EQ(rtp.padding_bit(), padding);
    EXPECT_EQ(rtp.extension_bit(), extension);
    EXPECT_EQ(rtp.csrc_count(), csrc_count);
    EXPECT_EQ(rtp.marker_bit(), marker);
    EXPECT_EQ(rtp.payload_type(), payload_type);
    EXPECT_EQ(rtp.sequence_number(), sequence_number);
    EXPECT_EQ(rtp.timestamp(), timestamp);
    EXPECT_EQ(rtp.ssrc_id(), ssrc_id);

    auto csrc_id_values = rtp.csrc_ids();
    for (size_t i = 0; i < csrc_count; ++i) {
        EXPECT_EQ(csrc_id_values[i], Endian::host_to_be(csrc_ids[i]));
    }

    EXPECT_EQ(rtp.extension_profile(), profile);
    EXPECT_EQ(rtp.extension_length(), extension_length);

    auto extension_data_values = rtp.extension_data();
    for (size_t i = 0; i < extension_length; ++i) {
        EXPECT_EQ(extension_data_values[i], Endian::host_to_be(extension_data[i]));
    }

    EXPECT_EQ(rtp.padding_size(), padding_size);
    EXPECT_EQ(rtp.header_size(), PACKET_SIZE - PAYLOAD_SIZE - padding_size);

    auto inner_pdu_payload = rtp.inner_pdu()->serialize();
    EXPECT_TRUE(std::equal(inner_pdu_payload.begin(), inner_pdu_payload.end(), payload));

    auto raw_pdu = RawPDU(payload, PAYLOAD_SIZE);
    auto raw_pdu_payload = raw_pdu.serialize();
    EXPECT_EQ(rtp.inner_pdu()->size(), raw_pdu.size());
    EXPECT_EQ(inner_pdu_payload, raw_pdu_payload);
}

TEST_F(RTPTest, SearchAndRemoveCSRCID) {
    auto rtp = RTP{};

    for (auto csrc_id : csrc_ids) {
        rtp.add_csrc_id(csrc_id);
    }

    for (size_t i = 0; i < csrc_count; ++i) {
        EXPECT_TRUE(rtp.search_csrc_id(csrc_ids[i]));
    }

    EXPECT_FALSE(rtp.search_csrc_id(0));
    EXPECT_FALSE(rtp.remove_csrc_id(0));
    EXPECT_TRUE(rtp.remove_csrc_id(csrc_ids[0]));
    EXPECT_FALSE(rtp.search_csrc_id(csrc_ids[0]));
}

TEST_F(RTPTest, SearchAndRemoveExtensionData) {
    auto rtp = RTP{};

    for (auto data : extension_data) {
        rtp.add_extension_data(data);
    }

    for (size_t i = 0; i < extension_length; ++i) {
        EXPECT_TRUE(rtp.search_extension_data(extension_data[i]));
    }

    EXPECT_FALSE(rtp.search_extension_data(0));
    EXPECT_FALSE(rtp.remove_extension_data(0));
    EXPECT_TRUE(rtp.remove_extension_data(extension_data[0]));
    EXPECT_FALSE(rtp.search_extension_data(extension_data[0]));
}

TEST_F(RTPTest, OuterUDP) {
    auto pkt = EthernetII{dst_addr, src_addr} / IP{dst_ip, src_ip} / UDP{dport, sport} / RTP{expected_packet, PACKET_SIZE};

    auto udp = pkt.find_pdu<UDP>();
    ASSERT_TRUE(udp != nullptr);
    EXPECT_EQ(udp->dport(), dport);
    EXPECT_EQ(udp->sport(), sport);

    auto rtp = udp->find_pdu<RTP>();
    ASSERT_TRUE(rtp != nullptr);
    EXPECT_EQ(rtp->header_size(), PACKET_SIZE - PAYLOAD_SIZE - padding_size);
    EXPECT_EQ(rtp->trailer_size(), padding_size);
    EXPECT_EQ(rtp->size(), PACKET_SIZE);
    EXPECT_EQ(rtp->inner_pdu()->size(), PAYLOAD_SIZE);
    auto inner_pdu_payload = rtp->inner_pdu()->serialize();
    EXPECT_TRUE(std::equal(inner_pdu_payload.begin(), inner_pdu_payload.end(), payload));
}

TEST_F(RTPTest, PaddingSizeTooLarge) {
    EXPECT_THROW((RTP{invalid_packet_one, sizeof(invalid_packet_one)}), malformed_packet);
}

TEST_F(RTPTest, PaddingBitSetWithoutPadding) {
    EXPECT_THROW((RTP{invalid_packet_two, sizeof(invalid_packet_two)}), malformed_packet);
}

TEST_F(RTPTest, PacketWithInvalidZeroPaddingValue) {
    EXPECT_THROW((RTP{packet_with_zero_padding_value, sizeof(packet_with_zero_padding_value)}), malformed_packet);
}

TEST_F(RTPTest, PacketWithoutData) {
    auto rtp = RTP{packet_without_data_one, sizeof(packet_without_data_one)};
    EXPECT_EQ(rtp.size(), sizeof(packet_without_data_one));
    EXPECT_EQ(rtp.header_size(), sizeof(packet_without_data_one));
    EXPECT_EQ(rtp.inner_pdu(), nullptr);
    EXPECT_EQ(rtp.padding_size(), 0);

    const uint8_t padding_size_ = 7;
    rtp = RTP{packet_without_data_two, sizeof(packet_without_data_two)};
    EXPECT_EQ(rtp.size(), sizeof(packet_without_data_two));
    EXPECT_EQ(rtp.header_size(), sizeof(packet_without_data_two) - padding_size_);
    EXPECT_EQ(rtp.inner_pdu(), nullptr);
    EXPECT_EQ(rtp.padding_size(), padding_size_);
}

TEST_F(RTPTest, PacketWithZeroExtensionLength) {
    auto rtp = RTP{packet_with_zero_extension_length, sizeof(packet_with_zero_extension_length)};
    EXPECT_EQ(rtp.size(), sizeof(packet_with_zero_extension_length));
    EXPECT_EQ(rtp.header_size(), sizeof(packet_with_zero_extension_length));
    EXPECT_EQ(rtp.extension_profile(), 0x5697);
    EXPECT_EQ(rtp.extension_length(), 0);
    EXPECT_EQ(rtp.extension_data().size(), 0);
}
