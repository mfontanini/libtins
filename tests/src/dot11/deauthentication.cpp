#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
#include "tests/dot11.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11DeauthenticationTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11DeauthenticationTest::expected_packet[] = { 
    '\xc1', '\x01', 'O', '#', '\x00', '\x01', '\x02', '\x03', '\x04', 
    '\x05', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x02', 
    '\x03', '\x04', '\x05', '\x06', '\x07', '\x00', '\x00', '\xf3', 
    '\x92'
};

void test_equals(const Dot11Deauthentication &dot1, const Dot11Deauthentication &dot2) {
    EXPECT_EQ(dot1.reason_code(), dot2.reason_code());
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11Deauthentication &dot11) {
    test_equals_expected(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.reason_code(), 0x92f3);
    EXPECT_EQ(dot11.subtype(), Dot11::DEAUTH);
}

TEST_F(Dot11DeauthenticationTest, Constructor) {
    Dot11Deauthentication dot11;
    test_equals_empty(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.reason_code(), 0);
    EXPECT_EQ(dot11.subtype(), Dot11::DEAUTH);
}

TEST_F(Dot11DeauthenticationTest, ConstructorFromBuffer) {
    Dot11Deauthentication dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11DeauthenticationTest, CopyConstructor) {
    Dot11Deauthentication dot1(expected_packet, sizeof(expected_packet));
    Dot11Deauthentication dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11DeauthenticationTest, CopyAssignmentOperator) {
    Dot11Deauthentication dot1(expected_packet, sizeof(expected_packet));
    Dot11Deauthentication dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11DeauthenticationTest, ReasonCode) {
    Dot11Deauthentication dot11;
    dot11.reason_code(0x92f3);
    EXPECT_EQ(dot11.reason_code(), 0x92f3);
}

TEST_F(Dot11DeauthenticationTest, ClonePDU) {
    Dot11Deauthentication dot1(expected_packet, sizeof(expected_packet));
    std::auto_ptr<Dot11Deauthentication> dot2(dot1.clone_pdu());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11DeauthenticationTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11Deauthentication *inner = dot11->find_inner_pdu<Dot11Deauthentication>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

TEST_F(Dot11DeauthenticationTest, Serialize) {
    Dot11Deauthentication pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

