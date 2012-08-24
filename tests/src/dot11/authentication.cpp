#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
#include "tests/dot11.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11AuthenticationTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11AuthenticationTest::expected_packet[] = { 
    '\xb1', '\x01', 'O', '#', '\x00', '\x01', '\x02', '\x03', '\x04', 
    '\x05', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x02', 
    '\x03', '\x04', '\x05', '\x06', '\x07', '\x00', '\x00', '\xa2', 
    '(', ':', '\xf2', '\xf3', '\x92'
};

void test_equals(const Dot11Authentication &dot1, const Dot11Authentication &dot2) {
    EXPECT_EQ(dot1.status_code(), dot2.status_code());
    EXPECT_EQ(dot1.auth_seq_number(), dot2.auth_seq_number());
    EXPECT_EQ(dot1.auth_algorithm(), dot2.auth_algorithm());
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11Authentication &dot11) {
    test_equals_expected(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.status_code(), 0x92f3);
    EXPECT_EQ(dot11.auth_seq_number(), 0xf23a);    
    EXPECT_EQ(dot11.auth_algorithm(), 0x28a2);
    EXPECT_EQ(dot11.subtype(), Dot11::AUTH);
}

TEST_F(Dot11AuthenticationTest, Constructor) {
    Dot11Authentication dot11;
    test_equals_empty(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.status_code(), 0);
    EXPECT_EQ(dot11.auth_seq_number(), 0);
    EXPECT_EQ(dot11.auth_algorithm(), 0);
    EXPECT_EQ(dot11.subtype(), Dot11::AUTH);
}

TEST_F(Dot11AuthenticationTest, ConstructorFromBuffer) {
    Dot11Authentication dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11AuthenticationTest, CopyConstructor) {
    Dot11Authentication dot1(expected_packet, sizeof(expected_packet));
    Dot11Authentication dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11AuthenticationTest, CopyAssignmentOperator) {
    Dot11Authentication dot1(expected_packet, sizeof(expected_packet));
    Dot11Authentication dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11AuthenticationTest, ClonePDU) {
    Dot11Authentication dot1(expected_packet, sizeof(expected_packet));
    std::auto_ptr<Dot11Authentication> dot2(dot1.clone_pdu());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11AuthenticationTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11Authentication *inner = dot11->find_inner_pdu<Dot11Authentication>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

