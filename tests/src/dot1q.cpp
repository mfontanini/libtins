#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "dot1q.h"
#include "arp.h"
#include "ethernetII.h"

using namespace std;
using namespace Tins;

class Dot1QTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    
    void test_equals(const Dot1Q &pdu1, const Dot1Q &pdu2);
};

const uint8_t Dot1QTest::expected_packet[] = { 
    255, 255, 255, 255, 255, 255, 0, 25, 6, 234, 184, 193, 129, 0, 176, 
    123, 8, 6, 0, 1, 8, 0, 6, 4, 0, 2, 0, 25, 6, 234, 184, 193, 192, 168, 
    123, 1, 255, 255, 255, 255, 255, 255, 192, 168, 123, 1, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

};

TEST_F(Dot1QTest, DefaultConstructor) {
    Dot1Q dot1;
    EXPECT_EQ(0, dot1.payload_type());
    EXPECT_EQ(0, dot1.priority());
    EXPECT_EQ(0, dot1.cfi());
    EXPECT_EQ(0, dot1.id());
}

TEST_F(Dot1QTest, ConstructorFromBuffer) {
    EthernetII eth(expected_packet, sizeof(expected_packet));
    const Dot1Q *dot1 = eth.find_pdu<Dot1Q>();
    ASSERT_TRUE(dot1);
    EXPECT_EQ(0x806, dot1->payload_type());
    EXPECT_EQ(5, dot1->priority());
    EXPECT_EQ(1, dot1->cfi());
    EXPECT_EQ(123, dot1->id());
    
    const ARP *arp = dot1->find_pdu<ARP>();
    ASSERT_TRUE(arp);
    // just to check it the offset's OK
    EXPECT_EQ(ARP::hwaddress_type("00:19:06:ea:b8:c1"), arp->sender_hw_addr());
}

TEST_F(Dot1QTest, Serialize) {
    EthernetII eth(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = eth.serialize();
    EXPECT_EQ(
        PDU::serialization_type(expected_packet, expected_packet + sizeof(expected_packet)),
        buffer
    );
}

TEST_F(Dot1QTest, PayloadType) {
    Dot1Q dot1;
    dot1.payload_type(0x9283);
    EXPECT_EQ(0x9283, dot1.payload_type());
}

TEST_F(Dot1QTest, Priority) {
    Dot1Q dot1;
    dot1.priority(5);
    EXPECT_EQ(5, dot1.priority());
}

TEST_F(Dot1QTest, CFI) {
    Dot1Q dot1;
    dot1.cfi(1);
    EXPECT_EQ(1, dot1.cfi());
}

TEST_F(Dot1QTest, Id) {
    Dot1Q dot1;
    dot1.id(3543);
    EXPECT_EQ(3543, dot1.id());
}
