#include "dot11/dot11_assoc.h"

#ifdef TINS_HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11_mgmt.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11ReAssocRequestTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11ReAssocRequestTest::expected_packet[] = { 
    33, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 
    0, 0, 21, 32, 243, 146, 3, 4, 5, 6, 7, 8
};

void test_equals(const Dot11ReAssocRequest& dot1, const Dot11ReAssocRequest& dot2) {
    test_equals(dot1.capabilities(), dot2.capabilities());
    EXPECT_EQ(dot1.listen_interval(), dot2.listen_interval());
    EXPECT_EQ(dot1.current_ap(), dot2.current_ap());
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11ReAssocRequest& dot11) {
    test_equals_expected(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.listen_interval(), 0x92f3);
    EXPECT_EQ(dot11.subtype(), Dot11::REASSOC_REQ);
}

TEST_F(Dot11ReAssocRequestTest, Constructor) {
    Dot11ReAssocRequest dot11;
    test_equals_empty(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.listen_interval(), 0);
    EXPECT_EQ(dot11.current_ap(), address_type());
    EXPECT_EQ(dot11.subtype(), Dot11::REASSOC_REQ);
}

TEST_F(Dot11ReAssocRequestTest, ConstructorFromBuffer) {
    Dot11ReAssocRequest dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11ReAssocRequestTest, CopyConstructor) {
    Dot11ReAssocRequest dot1(expected_packet, sizeof(expected_packet));
    Dot11ReAssocRequest dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11ReAssocRequestTest, CopyAssignmentOperator) {
    Dot11ReAssocRequest dot1(expected_packet, sizeof(expected_packet));
    Dot11ReAssocRequest dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11ReAssocRequestTest, ListenInterval) {
    Dot11ReAssocRequest dot11;
    dot11.listen_interval(0x92fd);
    EXPECT_EQ(dot11.listen_interval(), 0x92fd);
}

TEST_F(Dot11ReAssocRequestTest, CurrentAP) {
    Dot11ReAssocRequest dot11;
    dot11.current_ap("00:01:02:03:04:05");
    EXPECT_EQ(dot11.current_ap(), "00:01:02:03:04:05");
}

TEST_F(Dot11ReAssocRequestTest, ClonePDU) {
    Dot11ReAssocRequest dot1(expected_packet, sizeof(expected_packet));
    Internals::smart_ptr<Dot11ReAssocRequest>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11ReAssocRequestTest, FromBytes) {
    Internals::smart_ptr<PDU>::type dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get() != NULL);
    const Dot11ReAssocRequest* inner = dot11->find_pdu<Dot11ReAssocRequest>();
    ASSERT_TRUE(inner != NULL);
    test_equals_expected(*inner);
}

TEST_F(Dot11ReAssocRequestTest, Serialize) {
    Dot11ReAssocRequest pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

#endif // TINS_HAVE_DOT11
