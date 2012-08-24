#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
#include "tests/dot11.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11ProbeRequestTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11ProbeRequestTest::expected_packet[] = { 
    'A', '\x01', 'O', '#', '\x00', '\x01', '\x02', '\x03', '\x04', 
    '\x05', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x02', 
    '\x03', '\x04', '\x05', '\x06', '\x07', '\x00', '\x00'
};

void test_equals(const Dot11ProbeRequest &dot1, const Dot11ProbeRequest &dot2) {
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11ProbeRequest &dot11) {
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
    std::auto_ptr<Dot11ProbeRequest> dot2(dot1.clone_pdu());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11ProbeRequestTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11ProbeRequest *inner = dot11->find_inner_pdu<Dot11ProbeRequest>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

