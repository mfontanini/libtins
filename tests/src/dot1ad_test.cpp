#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include <tins/dot1ad.h>
#include <tins/dot1q.h>
#include <tins/arp.h>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/rawpdu.h>
#include <tins/ethernetII.h>

using namespace Tins;

class Dot1ADTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    static const uint8_t double_tag_packet[];

    void test_equals(const Dot1AD& pdu1, const Dot1AD& pdu2);
};

const uint8_t Dot1ADTest::expected_packet[] = {
    222, 173, 202, 255, 238, 0, 0, 0, 0, 0, 0, 0, 136, 168, 176, 15,
    129, 0, 128, 30, 8, 0, 69, 0, 0, 52, 0, 1, 0, 0, 128, 6, 122, 22, 0,
    0, 0, 0, 192, 168, 0, 5, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 80, 0,
    127, 166, 253, 69, 0, 0, 72, 101, 108, 108, 111, 32, 119, 111, 114,
    108, 100, 33
};

const uint8_t Dot1ADTest::double_tag_packet[] = {
    222, 173, 202, 255, 238, 0, 0, 0, 0, 0, 0, 0, 129, 0, 176, 15,
    129, 0, 128, 30, 8, 0, 69, 0, 0, 52, 0, 1, 0, 0, 128, 6, 122, 22, 0,
    0, 0, 0, 192, 168, 0, 5, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 80, 0,
    127, 166, 253, 69, 0, 0, 72, 101, 108, 108, 111, 32, 119, 111, 114,
    108, 100, 33
};

TEST_F(Dot1ADTest, DefaultConstructor) {
    Dot1AD dot1ad;
    EXPECT_EQ(PDU::DOT1AD, dot1ad.pdu_type());
    EXPECT_EQ(0, dot1ad.payload_type());
    EXPECT_EQ(0, dot1ad.priority());
    EXPECT_EQ(0, dot1ad.cfi());
    EXPECT_EQ(0, dot1ad.id());
}

TEST_F(Dot1ADTest, ConstructorFromBuffer) {
    EthernetII eth(expected_packet, sizeof(expected_packet));
    const Dot1AD* dot1ad = eth.find_pdu<Dot1AD>();
    ASSERT_TRUE(dot1ad != NULL);
    EXPECT_EQ(0x8100, dot1ad->payload_type());
    EXPECT_EQ(5, dot1ad->priority());
    EXPECT_EQ(1, dot1ad->cfi());
    EXPECT_EQ(15, dot1ad->id());

    const IP* ip = dot1ad->find_pdu<IP>();
    ASSERT_TRUE(ip != NULL);
    // just to check it the offset's OK
    EXPECT_EQ(IP::address_type("192.168.0.5"), ip->dst_addr());
}

TEST_F(Dot1ADTest, Serialize) {
    EthernetII eth(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = eth.serialize();
    EXPECT_EQ(
        PDU::serialization_type(expected_packet, expected_packet + sizeof(expected_packet)),
        buffer
    );
}

TEST_F(Dot1ADTest, PayloadType) {
    Dot1AD dot1ad;
    dot1ad.payload_type(0x9281);
    EXPECT_EQ(0x9281, dot1ad.payload_type());
}

TEST_F(Dot1ADTest, Priority) {
    Dot1AD dot1ad;
    dot1ad.priority(4);
    EXPECT_EQ(4, dot1ad.priority());
}

TEST_F(Dot1ADTest, CFI) {
    Dot1AD dot1ad;
    dot1ad.cfi(1);
    EXPECT_EQ(1, dot1ad.cfi());
}

TEST_F(Dot1ADTest, Id) {
    Dot1AD dot1ad;
    dot1ad.id(1927);
    EXPECT_EQ(1927, dot1ad.id());
}

TEST_F(Dot1ADTest, SerializeAfterInnerPduRemoved) {
    EthernetII eth1 = EthernetII() / Dot1AD(15) / Dot1Q(30) / IP();
    eth1.serialize();
    eth1.rfind_pdu<Dot1AD>().inner_pdu(0);

    PDU::serialization_type buffer = eth1.serialize();
    EthernetII eth2(&buffer[0], buffer.size());
    EXPECT_EQ(eth1.size(), eth2.size());
}

TEST_F(Dot1ADTest, DoubleDot1QSerializedToDot1AD) {
    EthernetII eth(double_tag_packet, sizeof(double_tag_packet));
    PDU::serialization_type buffer = eth.serialize();
    EXPECT_EQ(
        PDU::serialization_type(expected_packet, expected_packet + sizeof(expected_packet)),
        buffer
    );
}
