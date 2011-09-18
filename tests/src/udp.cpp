#include <gtest/gtest.h>
#include <cstring>
#include <stdint.h>
#include "udp.h"
#include "pdu.h"


using namespace std;
using namespace Tins;


class UDPTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
};

const uint8_t UDPTest::expected_packet[] = {'\xf5', '\x1a', 'G', '\xf1', '\x04', 'S', '\x00', '\x00'};


TEST_F(UDPTest, DefaultContructor) {
    UDP udp;
    EXPECT_EQ(udp.dport(), 0);
    EXPECT_EQ(udp.sport(), 0);
    EXPECT_FALSE(udp.inner_pdu());
}

TEST_F(UDPTest, CompleteConstructor) {
    UDP *inner = new UDP(0x48fa, 0x716b);
    UDP udp(0x1234, 0x4321, inner);
    EXPECT_EQ(udp.dport(), 0x1234);
    EXPECT_EQ(udp.sport(), 0x4321);
    EXPECT_TRUE(udp.inner_pdu() == inner);
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

TEST_F(UDPTest, CopyConstructor) {
    UDP udp1;
    udp1.dport(0x1234);
    udp1.sport(0x4321);
    udp1.length(0xdead);
    
    UDP udp2(udp1);
    EXPECT_EQ(udp2.sport(), udp1.sport());
    EXPECT_EQ(udp2.dport(), udp1.dport());
    EXPECT_EQ(udp2.length(), udp1.length());
    EXPECT_EQ(udp2.size(), udp1.size());
    EXPECT_EQ(udp2.header_size(), udp1.header_size());
}

TEST_F(UDPTest, CopyAssignmentOperator) {
    UDP udp1;
    udp1.dport(0x1234);
    udp1.sport(0x4321);
    udp1.length(0xdead);
    
    UDP udp2 = udp1;
    EXPECT_EQ(udp2.sport(), udp1.sport());
    EXPECT_EQ(udp2.dport(), udp1.dport());
    EXPECT_EQ(udp2.length(), udp1.length());
    EXPECT_EQ(udp2.size(), udp1.size());
    EXPECT_EQ(udp2.header_size(), udp1.header_size());
}

TEST_F(UDPTest, ClonePDU) {
    UDP udp1;
    uint16_t sport = 0x1234, dport = 0x4321, length = 0xdead;
    udp1.dport(dport);
    udp1.sport(sport);
    udp1.length(length);
    
    UDP *udp2 = static_cast<UDP*>(udp1.clone_pdu());
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
    
    uint32_t size;
    uint8_t *buffer = udp1.serialize(size);
    ASSERT_TRUE(buffer);
    
    UDP udp2(udp1);
    uint32_t size2;
    uint8_t *buffer2 = udp2.serialize(size2);
    ASSERT_EQ(size, size2);
    EXPECT_TRUE(memcmp(buffer, buffer2, size) == 0);
    delete[] buffer;
    delete[] buffer2;
}

TEST_F(UDPTest, ConstructorFromBuffer) {
    UDP udp1(expected_packet, sizeof(expected_packet));
    uint32_t size;
    uint8_t *buffer = udp1.serialize(size);
    
    EXPECT_EQ(size, sizeof(expected_packet));
    EXPECT_EQ(udp1.dport(), 0x47f1);
    EXPECT_EQ(udp1.sport(), 0xf51a);
    EXPECT_EQ(udp1.length(), 0x453);
    
    UDP udp2(buffer, size);
    EXPECT_EQ(udp1.dport(), udp2.dport());
    EXPECT_EQ(udp1.sport(), udp2.sport());
    EXPECT_EQ(udp1.length(), udp2.length());
    EXPECT_EQ(udp1.size(), udp2.size());
    EXPECT_EQ(udp1.header_size(), udp2.header_size());
}
