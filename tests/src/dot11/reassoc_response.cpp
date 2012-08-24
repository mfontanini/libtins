#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
#include "tests/dot11.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11ReAssocResponseTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11ReAssocResponseTest::expected_packet[] = { 
    '1', '\x01', 'O', '#', '\x00', '\x01', '\x02', '\x03', '\x04', 
    '\x05', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x02', 
    '\x03', '\x04', '\x05', '\x06', '\x07', '\x00', '\x00', '\x15', 
    ' ', '\xf3', '\x92', ':', '\xf2'
};

void test_equals(const Dot11ReAssocResponse &dot1, const Dot11ReAssocResponse &dot2) {
    test_equals(dot1.capabilities(), dot2.capabilities());
    EXPECT_EQ(dot1.status_code(), dot2.status_code());
    EXPECT_EQ(dot1.aid(), dot2.aid());
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11ReAssocResponse &dot11) {
    test_equals_expected(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.status_code(), 0x92f3);
    EXPECT_EQ(dot11.aid(), 0xf23a);
    EXPECT_EQ(dot11.subtype(), Dot11::REASSOC_RESP);
}

TEST_F(Dot11ReAssocResponseTest, Constructor) {
    Dot11ReAssocResponse dot11;
    test_equals_empty(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.status_code(), 0);
    EXPECT_EQ(dot11.aid(), 0);
    EXPECT_EQ(dot11.subtype(), Dot11::REASSOC_RESP);
}

TEST_F(Dot11ReAssocResponseTest, ConstructorFromBuffer) {
    Dot11ReAssocResponse dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11ReAssocResponseTest, CopyConstructor) {
    Dot11ReAssocResponse dot1(expected_packet, sizeof(expected_packet));
    Dot11ReAssocResponse dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11ReAssocResponseTest, CopyAssignmentOperator) {
    Dot11ReAssocResponse dot1(expected_packet, sizeof(expected_packet));
    Dot11ReAssocResponse dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11ReAssocResponseTest, ClonePDU) {
    Dot11ReAssocResponse dot1(expected_packet, sizeof(expected_packet));
    std::auto_ptr<Dot11ReAssocResponse> dot2(dot1.clone_pdu());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11ReAssocResponseTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11ReAssocResponse *inner = dot11->find_inner_pdu<Dot11ReAssocResponse>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

