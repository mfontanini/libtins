#include <gtest/gtest.h>
#include <cstring>
#include <stdint.h>
#include "udp.h"
#include "ip.h"


using namespace std;
using namespace Tins;


class UDPTest : public testing::Test {
public:
    static const uint8_t expected_packet[], checksum_packet[];
    
    void test_equals(const UDP& udp1, const UDP& udp2);
};

const uint8_t UDPTest::expected_packet[] = {
    245, 26, 71, 241, 8, 0, 0, 0
};

const uint8_t UDPTest::checksum_packet[] = {
    69, 0, 0, 48, 35, 109, 64, 0, 64, 17, 25, 78, 0, 0, 0, 0, 127, 0, 0, 
    1, 5, 57, 155, 11, 0, 28, 84, 167, 97, 115, 100, 97, 115, 100, 115, 
    97, 115, 100, 97, 115, 100, 115, 97, 100, 97, 115, 100, 10
};


void UDPTest::test_equals(const UDP& udp1, const UDP& udp2) {
    EXPECT_EQ(udp1.dport(), udp2.dport());
    EXPECT_EQ(udp1.sport(), udp2.sport());
    EXPECT_EQ(udp1.length(), udp2.length());
    EXPECT_EQ(udp1.size(), udp2.size());
    EXPECT_EQ(udp1.header_size(), udp2.header_size());
    EXPECT_EQ(bool(udp1.inner_pdu()), bool(udp2.inner_pdu()));
}

TEST_F(UDPTest, DefaultConstructor) {
    UDP udp;
    EXPECT_EQ(udp.dport(), 0);
    EXPECT_EQ(udp.sport(), 0);
    EXPECT_FALSE(udp.inner_pdu());
}

TEST_F(UDPTest, ChecksumCheck) {
    IP pkt1(checksum_packet, sizeof(checksum_packet)); 
    const UDP &udp1 = pkt1.rfind_pdu<UDP>();
    uint16_t checksum = udp1.checksum();
    
    IP::serialization_type buffer = pkt1.serialize();
    IP pkt2(&buffer[0], buffer.size());
    const UDP &udp2 = pkt2.rfind_pdu<UDP>();
    EXPECT_EQ(checksum, udp2.checksum());
    EXPECT_EQ(udp1.checksum(), udp2.checksum());
}

TEST_F(UDPTest, CopyConstructor) {
    UDP udp1(expected_packet, sizeof(expected_packet));
    UDP udp2(udp1);
    test_equals(udp1, udp2);
}

TEST_F(UDPTest, CopyAssignmentOperator) {
    UDP udp1(expected_packet, sizeof(expected_packet));
    UDP udp2;
    udp2 = udp1;
    test_equals(udp1, udp2);
}

TEST_F(UDPTest, CompleteConstructor) {
    UDP udp(0x1234, 0x4321);
    EXPECT_EQ(udp.dport(), 0x1234);
    EXPECT_EQ(udp.sport(), 0x4321);
}

TEST_F(UDPTest, DPort) {
    UDP udp;
    uint16_t port = 0x1234;
    udp.dport(port);
    ASSERT_EQ(udp.dport(), port);
}

TEST_F(UDPTest, SPort) {
    UDP udp;
    uint16_t port = 0x1234;
    udp.sport(port);
    ASSERT_EQ(udp.sport(), port);
}

TEST_F(UDPTest, Length) {
    UDP udp;
    uint16_t length = 0x1234;
    udp.length(length);
    ASSERT_EQ(udp.length(), length);
}

TEST_F(UDPTest, PDUType) {
    UDP udp;
    EXPECT_EQ(udp.pdu_type(), PDU::UDP);
}

TEST_F(UDPTest, ClonePDU) {
    UDP udp1;
    uint16_t sport = 0x1234, dport = 0x4321, length = 0xdead;
    udp1.dport(dport);
    udp1.sport(sport);
    udp1.length(length);
    
    UDP *udp2 = udp1.clone();
    ASSERT_TRUE(udp2);
    EXPECT_EQ(udp2->sport(), sport);
    EXPECT_EQ(udp2->dport(), dport);
    EXPECT_EQ(udp2->length(), length);
    EXPECT_EQ(udp2->pdu_type(), PDU::UDP);
    delete udp2;
}

TEST_F(UDPTest, Serialize) {
    UDP udp1;
    uint16_t sport = 0x1234, dport = 0x4321, length = 0xdead;
    udp1.dport(dport);
    udp1.sport(sport);
    udp1.length(length);
    
    PDU::serialization_type buffer = udp1.serialize();
    
    UDP udp2(udp1);
    PDU::serialization_type buffer2 = udp2.serialize();
    EXPECT_EQ(buffer, buffer2);
}

TEST_F(UDPTest, ConstructorFromBuffer) {
    UDP udp1(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = udp1.serialize();
    
    EXPECT_EQ(buffer.size(), sizeof(expected_packet));
    EXPECT_EQ(udp1.dport(), 0x47f1);
    EXPECT_EQ(udp1.sport(), 0xf51a);
    EXPECT_EQ(udp1.length(), 8);
    
    UDP udp2(&buffer[0], buffer.size());
    EXPECT_EQ(udp1.dport(), udp2.dport());
    EXPECT_EQ(udp1.sport(), udp2.sport());
    EXPECT_EQ(udp1.length(), udp2.length());
    EXPECT_EQ(udp1.size(), udp2.size());
    EXPECT_EQ(udp1.header_size(), udp2.header_size());
}
