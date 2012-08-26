#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
#include "tests/dot11.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11AssocRequestTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
    //static void test_equals_expected(const Dot11Beacon&dot11);
};

const uint8_t Dot11AssocRequestTest::expected_packet[] = { 
    '\x01', '\x01', 'O', '#', '\x00', '\x01', '\x02', '\x03', '\x04', 
    '\x05', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x02', 
    '\x03', '\x04', '\x05', '\x06', '\x07', '\x00', '\x00', '\x15', 
    ' ', '\xf3', '\x92'
};

void test_equals(const Dot11AssocRequest &dot1, const Dot11AssocRequest &dot2) {
    test_equals(dot1.capabilities(), dot2.capabilities());
    EXPECT_EQ(dot1.listen_interval(), dot2.listen_interval());
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11AssocRequest &dot11) {
    test_equals_expected(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.listen_interval(), 0x92f3);
    EXPECT_EQ(dot11.subtype(), Dot11::ASSOC_REQ);
}

TEST_F(Dot11AssocRequestTest, Constructor) {
    Dot11AssocRequest dot11;
    test_equals_empty(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.listen_interval(), 0);
    EXPECT_EQ(dot11.subtype(), Dot11::ASSOC_REQ);
}

TEST_F(Dot11AssocRequestTest, ConstructorFromBuffer) {
    Dot11AssocRequest dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11AssocRequestTest, CopyConstructor) {
    Dot11AssocRequest dot1(expected_packet, sizeof(expected_packet));
    Dot11AssocRequest dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11AssocRequestTest, CopyAssignmentOperator) {
    Dot11AssocRequest dot1(expected_packet, sizeof(expected_packet));
    Dot11AssocRequest dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11AssocRequestTest, ListenInterval) {
    Dot11AssocRequest dot11;
    dot11.listen_interval(0x92fd);
    EXPECT_EQ(dot11.listen_interval(), 0x92fd);
}

TEST_F(Dot11AssocRequestTest, ClonePDU) {
    Dot11AssocRequest dot1(expected_packet, sizeof(expected_packet));
    std::auto_ptr<Dot11AssocRequest> dot2(dot1.clone_pdu());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11AssocRequestTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11AssocRequest *inner = dot11->find_inner_pdu<Dot11AssocRequest>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

TEST_F(Dot11AssocRequestTest, Serialize) {
    Dot11AssocRequest pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

