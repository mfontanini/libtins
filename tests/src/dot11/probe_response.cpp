#include "dot11/dot11_probe.h"

#ifdef HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11_mgmt.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11ProbeResponseTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11ProbeResponseTest::expected_packet[] = { 
    81, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 
    0, 0, 145, 138, 131, 39, 223, 152, 166, 23, 141, 146, 0, 0
};

void test_equals(const Dot11ProbeResponse &dot1, const Dot11ProbeResponse &dot2) {
    EXPECT_EQ(dot1.interval(), dot2.interval());
    EXPECT_EQ(dot1.timestamp(), dot2.timestamp());
    test_equals(
        static_cast<const Dot11ManagementFrame&>(dot1),
        static_cast<const Dot11ManagementFrame&>(dot2)
    );
}

void test_equals_expected(const Dot11ProbeResponse &dot11) {
    test_equals_expected(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.timestamp(), 0x17a698df27838a91ULL);
    EXPECT_EQ(dot11.interval(), 0x928d);
    EXPECT_EQ(dot11.subtype(), Dot11::PROBE_RESP);
}

TEST_F(Dot11ProbeResponseTest, Constructor) {
    Dot11ProbeResponse dot11;
    test_equals_empty(static_cast<const Dot11ManagementFrame&>(dot11));
    EXPECT_EQ(dot11.timestamp(), 0U);
    EXPECT_EQ(dot11.interval(), 0);
    EXPECT_EQ(dot11.subtype(), Dot11::PROBE_RESP);
}

TEST_F(Dot11ProbeResponseTest, ConstructorFromBuffer) {
    Dot11ProbeResponse dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11ProbeResponseTest, CopyConstructor) {
    Dot11ProbeResponse dot1(expected_packet, sizeof(expected_packet));
    Dot11ProbeResponse dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11ProbeResponseTest, CopyAssignmentOperator) {
    Dot11ProbeResponse dot1(expected_packet, sizeof(expected_packet));
    Dot11ProbeResponse dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11ProbeResponseTest, Interval) {
    Dot11ProbeResponse dot11;
    dot11.interval(0x92af);
    EXPECT_EQ(dot11.interval(), 0x92af);
}

TEST_F(Dot11ProbeResponseTest, Timestamp) {
    Dot11ProbeResponse dot11;
    dot11.timestamp(0x92af8a72df928a7cLL);
    EXPECT_EQ(dot11.timestamp(), 0x92af8a72df928a7cULL);
}

TEST_F(Dot11ProbeResponseTest, ClonePDU) {
    Dot11ProbeResponse dot1(expected_packet, sizeof(expected_packet));
    Internals::smart_ptr<Dot11ProbeResponse>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11ProbeResponseTest, FromBytes) {
    Internals::smart_ptr<PDU>::type dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11ProbeResponse *inner = dot11->find_pdu<Dot11ProbeResponse>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

TEST_F(Dot11ProbeResponseTest, Serialize) {
    Dot11ProbeResponse pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

#endif // HAVE_DOT11
