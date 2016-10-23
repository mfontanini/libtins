#include <gtest/gtest.h>
#include <cstring>
#include <stdint.h>
#include "udp.h"
#include "ip.h"
#include "ethernetII.h"

using namespace std;
using namespace Tins;


class UDPTest : public testing::Test {
public:
    static const uint8_t expected_packet[], checksum_packet[], 
                         checksum_packet2[], checksum_packet3[];
    
    void test_equals(const UDP& udp1, const UDP& udp2);
};

const uint8_t UDPTest::expected_packet[] = {
    245, 26, 71, 241, 8, 0, 0, 0
};

const uint8_t UDPTest::checksum_packet[] = {
    10, 128, 57, 251, 101, 187, 76, 128, 147, 141, 144, 65, 8, 0, 69, 0, 0, 
    70, 14, 223, 64, 0, 64, 17, 138, 252, 10, 0, 0, 54, 75, 75, 75, 75, 215, 
    173, 0, 53, 0, 50, 206, 155, 118, 39, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 
    48, 45, 101, 100, 103, 101, 45, 99, 104, 97, 116, 8, 102, 97, 99, 101, 
    98, 111, 111, 107, 3, 99, 111, 109, 0, 0, 1, 0, 1
};

const uint8_t UDPTest::checksum_packet2[] = {
    0, 20, 165, 53, 119, 224, 44, 240, 238, 33, 128, 46, 8, 0, 69, 184, 0, 
    200, 9, 187, 0, 0, 63, 17, 107, 202, 192, 168, 6, 224, 198, 199, 118, 
    152, 217, 252, 192, 0, 0, 180, 250, 82, 128, 0, 0, 106, 86, 129, 110, 
    22, 2, 46, 39, 16, 0, 0, 7, 111, 0, 0, 34, 42, 86, 129, 110, 20, 0, 14, 
    255, 229, 0, 0, 8, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0
};

const uint8_t UDPTest::checksum_packet3[] = {
    0, 20, 165, 53, 119, 224, 44, 240, 238, 33, 128, 46, 8, 0, 69, 184, 0, 
    200, 127, 204, 0, 0, 28, 17, 24, 185, 192, 168, 6, 224, 198, 199, 118, 
    152, 213, 50, 192, 0, 0, 180, 255, 255, 128, 0, 0, 29, 86, 130, 177, 
    157, 1, 46, 0, 0, 0, 0, 7, 111, 0, 0, 52, 134, 86, 130, 177, 132, 0, 
    5, 150, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void UDPTest::test_equals(const UDP& udp1, const UDP& udp2) {
    EXPECT_EQ(udp1.dport(), udp2.dport());
    EXPECT_EQ(udp1.sport(), udp2.sport());
    EXPECT_EQ(udp1.length(), udp2.length());
    EXPECT_EQ(udp1.size(), udp2.size());
    EXPECT_EQ(udp1.header_size(), udp2.header_size());
    EXPECT_EQ(udp1.inner_pdu() != NULL, udp2.inner_pdu() != NULL);
}

TEST_F(UDPTest, DefaultConstructor) {
    UDP udp;
    EXPECT_EQ(udp.dport(), 0);
    EXPECT_EQ(udp.sport(), 0);
    EXPECT_FALSE(udp.inner_pdu());
}

TEST_F(UDPTest, ChecksumCheck) {
    EthernetII pkt1(checksum_packet, sizeof(checksum_packet)); 
    const UDP& udp1 = pkt1.rfind_pdu<UDP>();
    uint16_t checksum = udp1.checksum();
    PDU::serialization_type buffer = pkt1.serialize();
    EXPECT_EQ(
        UDP::serialization_type(
            checksum_packet, 
            checksum_packet + sizeof(checksum_packet)
        ),
        buffer
    );

    EthernetII pkt2(&buffer[0], (uint32_t)buffer.size());
    const UDP& udp2 = pkt2.rfind_pdu<UDP>();
    EXPECT_EQ(checksum, udp2.checksum());
    EXPECT_EQ(udp1.checksum(), udp2.checksum());
}

TEST_F(UDPTest, ChecksumCheck2) {
    EthernetII pkt(checksum_packet2, sizeof(checksum_packet2));
    PDU::serialization_type buffer = pkt.serialize();
    EXPECT_EQ(
        UDP::serialization_type(
            checksum_packet2, 
            checksum_packet2 + sizeof(checksum_packet2)
        ),
        buffer
    );
    EXPECT_EQ(0xfa52, pkt.rfind_pdu<UDP>().checksum());
}

// This checksum's 0. We should set it to 0xffff instead
TEST_F(UDPTest, ChecksumCheck3) {
    EthernetII pkt(checksum_packet3, sizeof(checksum_packet3));
    PDU::serialization_type buffer = pkt.serialize();
    EXPECT_EQ(
        UDP::serialization_type(
            checksum_packet3, 
            checksum_packet3 + sizeof(checksum_packet3)
        ),
        buffer
    );
    EXPECT_EQ(0xffff, pkt.rfind_pdu<UDP>().checksum());
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
    
    UDP* udp2 = udp1.clone();
    ASSERT_TRUE(udp2 != NULL);
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
    
    UDP udp2(&buffer[0], (uint32_t)buffer.size());
    EXPECT_EQ(udp1.dport(), udp2.dport());
    EXPECT_EQ(udp1.sport(), udp2.sport());
    EXPECT_EQ(udp1.length(), udp2.length());
    EXPECT_EQ(udp1.size(), udp2.size());
    EXPECT_EQ(udp1.header_size(), udp2.header_size());
}
