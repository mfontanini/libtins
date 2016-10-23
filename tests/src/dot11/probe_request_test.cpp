#include "dot11/dot11_probe.h"

#ifdef TINS_HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11_mgmt.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11ProbeRequestTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11ProbeRequestTest::expected_packet[] = { 
    65, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 
    0, 0
};

void test_equals(const Dot11ProbeRequest& dot1, const Dot11ProbeRequest& dot2) {
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11ProbeRequest& dot11) {
    test_equals_expected(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.subtype(), Dot11::PROBE_REQ);
}

TEST_F(Dot11ProbeRequestTest, Constructor) {
    Dot11ProbeRequest dot11;
    test_equals_empty(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.subtype(), Dot11::PROBE_REQ);
}

TEST_F(Dot11ProbeRequestTest, ConstructorFromBuffer) {
    Dot11ProbeRequest dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11ProbeRequestTest, CopyConstructor) {
    Dot11ProbeRequest dot1(expected_packet, sizeof(expected_packet));
    Dot11ProbeRequest dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11ProbeRequestTest, CopyAssignmentOperator) {
    Dot11ProbeRequest dot1(expected_packet, sizeof(expected_packet));
    Dot11ProbeRequest dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11ProbeRequestTest, ClonePDU) {
    Dot11ProbeRequest dot1(expected_packet, sizeof(expected_packet));
    Internals::smart_ptr<Dot11ProbeRequest>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11ProbeRequestTest, FromBytes) {
    Internals::smart_ptr<PDU>::type dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get() != NULL);
    const Dot11ProbeRequest* inner = dot11->find_pdu<Dot11ProbeRequest>();
    ASSERT_TRUE(inner != NULL);
    test_equals_expected(*inner);
}

#endif // TINS_HAVE_DOT11
