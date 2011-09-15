#include <gtest/gtest.h>
#include <stdint.h>
#include "udp.h"
#include "pdu.h"


using namespace std;
using namespace Tins;



TEST(UDP, DefaultContructor) {
    UDP udp;
    EXPECT_EQ(udp.dport(), 0);
    EXPECT_EQ(udp.sport(), 0);
    EXPECT_FALSE(udp.inner_pdu());
}

TEST(UDP, DPort) {
    UDP udp;
    uint16_t port = 0x1234;
    udp.dport(port);
    ASSERT_EQ(udp.dport(), port);
}

TEST(UDP, SPort) {
    UDP udp;
    uint16_t port = 0x1234;
    udp.sport(port);
    ASSERT_EQ(udp.sport(), port);
}

TEST(UDP, Length) {
    UDP udp;
    uint16_t length = 0x1234;
    udp.length(length);
    ASSERT_EQ(udp.length(), length);
}

TEST(UDP, PDUType) {
    UDP udp;
    EXPECT_EQ(udp.pdu_type(), PDU::UDP);
}

TEST(UDP, CopyConstructor) {
    UDP udp1;
    udp1.dport(0x1234);
    udp1.sport(0x4321);
    udp1.length(0xdead);
    
    UDP udp2(udp1);
    EXPECT_EQ(udp2.sport(), udp1.sport());
    EXPECT_EQ(udp2.dport(), udp1.dport());
    EXPECT_EQ(udp2.length(), udp1.length());
}

TEST(UDP, CopyAssignmentOperator) {
    UDP udp1;
    udp1.dport(0x1234);
    udp1.sport(0x4321);
    udp1.length(0xdead);
    
    UDP udp2 = udp1;
    EXPECT_EQ(udp2.sport(), udp1.sport());
    EXPECT_EQ(udp2.dport(), udp1.dport());
    EXPECT_EQ(udp2.length(), udp1.length());
}

TEST(UDP, Clone) {
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

TEST(UDP, Serialize) {
    UDP udp1;
    uint16_t sport = 0x1234, dport = 0x4321, length = 0xdead;
    udp1.dport(dport);
    udp1.sport(sport);
    udp1.length(length);
    
    uint32_t size;
    uint8_t *buffer = udp1.serialize(size);
    ASSERT_TRUE(buffer);
    delete[] buffer;
}

TEST(UDP, BufferClone) {
    UDP udp1;
    uint16_t sport = 0x1234, dport = 0x4321, length = 0xdead;
    udp1.dport(dport);
    udp1.sport(sport);
    udp1.length(length);
    
    uint32_t size;
    uint8_t *buffer = udp1.serialize(size);
    ASSERT_TRUE(buffer);
    
    UDP udp2(buffer, size);
    EXPECT_EQ(udp2.sport(), udp1.sport());
    EXPECT_EQ(udp2.dport(), udp1.dport());
    EXPECT_EQ(udp2.length(), udp1.length());
    EXPECT_EQ(udp2.pdu_type(), PDU::UDP);
    
    delete[] buffer;
}




