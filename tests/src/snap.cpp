#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "snap.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class SNAPTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    
    void test_equals(const SNAP& snap1, const SNAP& snap2);
};

const uint8_t SNAPTest::expected_packet[] = {
    170, 170, 3, 0, 0, 1, 8, 0
};

TEST_F(SNAPTest, DefaultConstructor) {
    SNAP snap;
    EXPECT_EQ(snap.pdu_type(), PDU::SNAP);
    EXPECT_EQ(snap.dsap(), 0xaa);
    EXPECT_EQ(snap.ssap(), 0xaa);
    EXPECT_EQ(snap.eth_type(), 0);
    EXPECT_EQ(snap.org_code(), 0U);
    EXPECT_EQ(snap.control(), 3);
}

TEST_F(SNAPTest, CopyConstructor) {
    SNAP snap1;
    snap1.eth_type(0xfab1);
    snap1.org_code(0xfab1c3);
    snap1.control(0x1);
    SNAP snap2(snap1);
    test_equals(snap1, snap2);
}

TEST_F(SNAPTest, CopyAssignmentOperator) {
    SNAP snap1;
    snap1.eth_type(0xfab1);
    snap1.org_code(0xfab1c3);
    snap1.control(0x1);
    SNAP snap2 = snap1;
    test_equals(snap1, snap2);
}

TEST_F(SNAPTest, OrgCode) {
    SNAP snap; 
    snap.org_code(0xfab1c3); 
    
    EXPECT_EQ(snap.org_code(), 0xfab1c3U);
    EXPECT_EQ(snap.control(), 3);
}

TEST_F(SNAPTest, Control) {
    SNAP snap; 
    snap.control(0xfa); 
    
    EXPECT_EQ(snap.control(), 0xfa);
    EXPECT_EQ(snap.org_code(), 0U);
}

TEST_F(SNAPTest, EthType) {
    SNAP snap;
    snap.eth_type(0xfab1);
    EXPECT_EQ(snap.eth_type(), 0xfab1);
}

TEST_F(SNAPTest, Serialize) {
    SNAP snap1;
    snap1.eth_type(0xfab1);
    snap1.org_code(0xfab1c3);
    snap1.control(0x1);
    
    PDU::serialization_type buffer = snap1.serialize();
    
    SNAP snap2(snap1);
    PDU::serialization_type buffer2 = snap2.serialize();
    EXPECT_EQ(buffer, buffer2);
}

TEST_F(SNAPTest, ClonePDU) {
    SNAP snap1;
    snap1.eth_type(0xfab1);
    snap1.org_code(0xfab1c3);
    snap1.control(0x1);
    SNAP* snap2 = static_cast<SNAP*>(snap1.clone());
    ASSERT_TRUE(snap2 != NULL);
    test_equals(snap1, *snap2);
    
    delete snap2;
}

TEST_F(SNAPTest, ConstructorFromBuffer) {
    SNAP snap1(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = snap1.serialize();
    
    EXPECT_EQ(3, snap1.control());
    EXPECT_EQ(0xaa, snap1.dsap());
    EXPECT_EQ(0xaa, snap1.ssap());
    EXPECT_EQ(0x0800, snap1.eth_type()); 
    EXPECT_EQ(1U, snap1.org_code()); 
    
    SNAP snap2(&buffer[0], (uint32_t)buffer.size());
    test_equals(snap1, snap2);
}

void SNAPTest::test_equals(const SNAP& snap1, const SNAP& snap2) {
    EXPECT_EQ(snap1.dsap(), snap2.dsap());
    EXPECT_EQ(snap1.ssap(), snap2.ssap());
    EXPECT_EQ(snap1.control(), snap2.control());
    EXPECT_EQ(snap1.eth_type(), snap2.eth_type());
}
