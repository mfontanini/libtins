#include "dot11/dot11_assoc.h"

#ifdef TINS_HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11_mgmt.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11DisassocTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
    //static void test_equals_expected(const Dot11Beacon&dot11);
};

const uint8_t Dot11DisassocTest::expected_packet[] = { 
    161, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 
    7, 0, 0, 18, 35
};

void test_equals(const Dot11Disassoc& dot1, const Dot11Disassoc& dot2) {
    EXPECT_EQ(dot1.reason_code(), dot2.reason_code());
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11Disassoc& dot11) {
    test_equals_expected(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.reason_code(), 0x2312);
    EXPECT_EQ(dot11.subtype(), Dot11::DISASSOC);
}

TEST_F(Dot11DisassocTest, Constructor) {
    Dot11Disassoc dot11;
    test_equals_empty(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.reason_code(), 0);
    EXPECT_EQ(dot11.subtype(), Dot11::DISASSOC);
}

TEST_F(Dot11DisassocTest, ConstructorFromBuffer) {
    Dot11Disassoc dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11DisassocTest, CopyConstructor) {
    Dot11Disassoc dot1(expected_packet, sizeof(expected_packet));
    Dot11Disassoc dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11DisassocTest, CopyAssignmentOperator) {
    Dot11Disassoc dot1(expected_packet, sizeof(expected_packet));
    Dot11Disassoc dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11DisassocTest, ReasonCode) {
    Dot11Disassoc dot11;
    dot11.reason_code(0x92f3);
    EXPECT_EQ(dot11.reason_code(), 0x92f3);
}

TEST_F(Dot11DisassocTest, ClonePDU) {
    Dot11Disassoc dot1(expected_packet, sizeof(expected_packet));
    Internals::smart_ptr<Dot11Disassoc>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11DisassocTest, FromBytes) {
    Internals::smart_ptr<PDU>::type dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get() != NULL);
    const Dot11Disassoc* inner = dot11->find_pdu<Dot11Disassoc>();
    ASSERT_TRUE(inner != NULL);
    test_equals_expected(*inner);
}

TEST_F(Dot11DisassocTest, Serialize) {
    Dot11Disassoc pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

#endif // TINS_HAVE_DOT11
