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
    
    void test_equals(const SNAP &snap1, const SNAP &snap2);
};

const uint8_t SNAPTest::expected_packet[] = {'\xaa', '\xaa', '\x03', '\x00', '\x00', '\x00', 'z', '\xb1'};

TEST_F(SNAPTest, DefaultConstructor) {
    SNAP snap;
    EXPECT_EQ(snap.pdu_type(), PDU::SNAP);
    EXPECT_EQ(snap.dsap(), 0xaa);
    EXPECT_EQ(snap.ssap(), 0xaa);
    EXPECT_EQ(snap.eth_type(), 0);
    EXPECT_EQ(snap.poll(), 0);
    EXPECT_EQ(snap.org_code(), 0);
    EXPECT_EQ(snap.id(), 3);
}

TEST_F(SNAPTest, CopyConstructor) {
    SNAP snap1;
    snap1.eth_type(0xfab1);
    snap1.org_code(0xfab1c3);
    snap1.poll(0x1);
    snap1.id(0x1);
    SNAP snap2(snap1);
    test_equals(snap1, snap2);
}

TEST_F(SNAPTest, CopyAssignmentOperator) {
    SNAP snap1;
    snap1.eth_type(0xfab1);
    snap1.org_code(0xfab1c3);
    snap1.poll(0x1);
    snap1.id(0x1);
    SNAP snap2 = snap1;
    test_equals(snap1, snap2);
}

TEST_F(SNAPTest, Id) {
    SNAP snap;
    snap.id(0x1);
    EXPECT_EQ(snap.id(), 0x1);
}

TEST_F(SNAPTest, Poll) {
    SNAP snap;
    snap.poll(0x1);
    EXPECT_EQ(snap.poll(), 0x1);
}

TEST_F(SNAPTest, OrgCode) {
    SNAP snap;
    snap.org_code(0xfab1c3);
    EXPECT_EQ(snap.org_code(), 0xfab1c3);
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
    snap1.poll(0x1);
    snap1.id(0x1);
    
    uint32_t size;
    uint8_t *buffer = snap1.serialize(size);
    ASSERT_TRUE(buffer);
    
    SNAP snap2(snap1);
    uint32_t size2;
    uint8_t *buffer2 = snap2.serialize(size2);
    ASSERT_EQ(size, size2);
    EXPECT_TRUE(memcmp(buffer, buffer2, size) == 0);
    delete[] buffer;
    delete[] buffer2;
}

TEST_F(SNAPTest, ClonePDU) {
    SNAP snap1;
    snap1.eth_type(0xfab1);
    snap1.org_code(0xfab1c3);
    snap1.poll(0x1);
    snap1.id(0x1);
    SNAP *snap2 = static_cast<SNAP*>(snap1.clone_pdu());
    ASSERT_TRUE(snap2);
    test_equals(snap1, *snap2);
    
    delete snap2;
}

TEST_F(SNAPTest, ConstructorFromBuffer) {
    SNAP snap1(expected_packet, sizeof(expected_packet));
    uint32_t size;
    uint8_t *buffer = snap1.serialize(size);
    
    EXPECT_EQ(snap1.id(), 3);
    EXPECT_EQ(snap1.dsap(), 0xaa);
    EXPECT_EQ(snap1.ssap(), 0xaa);
    EXPECT_EQ(snap1.eth_type(), 0x7ab1);
    
    SNAP snap2(buffer, size);
    test_equals(snap1, snap2);
    delete[] buffer;
}

void SNAPTest::test_equals(const SNAP &snap1, const SNAP &snap2) {
    EXPECT_EQ(snap1.dsap(), snap2.dsap());
    EXPECT_EQ(snap1.ssap(), snap2.ssap());
    EXPECT_EQ(snap1.id(), snap2.id());
    EXPECT_EQ(snap1.eth_type(), snap2.eth_type());
}
