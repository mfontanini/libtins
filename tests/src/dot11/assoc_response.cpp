#include "dot11/dot11_assoc.h"

#ifdef HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11_mgmt.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11AssocResponseTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11AssocResponseTest::expected_packet[] = { 
    17, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 
    0, 0, 21, 32, 243, 146, 58, 242
};

void test_equals(const Dot11AssocResponse &dot1, const Dot11AssocResponse &dot2) {
    test_equals(dot1.capabilities(), dot2.capabilities());
    EXPECT_EQ(dot1.status_code(), dot2.status_code());
    EXPECT_EQ(dot1.aid(), dot2.aid());
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11AssocResponse &dot11) {
    test_equals_expected(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.status_code(), 0x92f3);
    EXPECT_EQ(dot11.aid(), 0xf23a);
    EXPECT_EQ(dot11.subtype(), Dot11::ASSOC_RESP);
}

TEST_F(Dot11AssocResponseTest, Constructor) {
    Dot11AssocResponse dot11;
    test_equals_empty(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.status_code(), 0);
    EXPECT_EQ(dot11.aid(), 0);
    EXPECT_EQ(dot11.subtype(), Dot11::ASSOC_RESP);
}

TEST_F(Dot11AssocResponseTest, ConstructorFromBuffer) {
    Dot11AssocResponse dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11AssocResponseTest, CopyConstructor) {
    Dot11AssocResponse dot1(expected_packet, sizeof(expected_packet));
    Dot11AssocResponse dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11AssocResponseTest, CopyAssignmentOperator) {
    Dot11AssocResponse dot1(expected_packet, sizeof(expected_packet));
    Dot11AssocResponse dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11AssocResponseTest, StatusCode) {
    Dot11AssocResponse dot11;
    dot11.status_code(0x92f3);
    EXPECT_EQ(dot11.status_code(), 0x92f3);
}

TEST_F(Dot11AssocResponseTest, AID) {
    Dot11AssocResponse dot11;
    dot11.aid(0x92f3);
    EXPECT_EQ(dot11.aid(), 0x92f3);
}

TEST_F(Dot11AssocResponseTest, ClonePDU) {
    Dot11AssocResponse dot1(expected_packet, sizeof(expected_packet));
    Internals::smart_ptr<Dot11AssocResponse>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11AssocResponseTest, FromBytes) {
    Internals::smart_ptr<PDU>::type dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11AssocResponse *inner = dot11->find_pdu<Dot11AssocResponse>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

TEST_F(Dot11AssocResponseTest, Serialize) {
    Dot11AssocResponse pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

#endif // HAVE_DOT11
