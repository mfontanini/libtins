#include "dot11/dot11_auth.h"

#ifdef HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11_mgmt.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11AuthenticationTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11AuthenticationTest::expected_packet[] = { 
    177, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 
    7, 0, 0, 162, 40, 58, 242, 243, 146
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

TEST_F(Dot11AuthenticationTest, StatusCode) {
    Dot11Authentication dot11;
    dot11.status_code(0x92f3);
    EXPECT_EQ(dot11.status_code(), 0x92f3);
}

TEST_F(Dot11AuthenticationTest, AuthSequenceNumber) {
    Dot11Authentication dot11;
    dot11.auth_seq_number(0x92f3);
    EXPECT_EQ(dot11.auth_seq_number(), 0x92f3);
}

TEST_F(Dot11AuthenticationTest, AuthAlgorithm) {
    Dot11Authentication dot11;
    dot11.auth_algorithm(0x92f3);
    EXPECT_EQ(dot11.auth_algorithm(), 0x92f3);
}

TEST_F(Dot11AuthenticationTest, ClonePDU) {
    Dot11Authentication dot1(expected_packet, sizeof(expected_packet));
    Internals::smart_ptr<Dot11Authentication>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11AuthenticationTest, FromBytes) {
    Internals::smart_ptr<PDU>::type dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11Authentication *inner = dot11->find_pdu<Dot11Authentication>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

TEST_F(Dot11AuthenticationTest, Serialize) {
    Dot11Authentication pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

#endif // HAVE_DOT11
