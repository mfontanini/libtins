#include "dot11/dot11_control.h"
#ifdef HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11AckTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const address_type Dot11AckTest::empty_addr;

const uint8_t Dot11AckTest::expected_packet[] = { 
    213, 1, 79, 35, 0, 1, 2, 3, 4, 5
};

void test_equals(const Dot11Ack &dot1, const Dot11Ack &dot2) {
    test_equals(
        static_cast<const Dot11&>(dot1),
        static_cast<const Dot11&>(dot2)
    );
}

void test_equals_expected(const Dot11Ack &dot11) {
    EXPECT_EQ(dot11.protocol(), 1);
    EXPECT_EQ(dot11.type(), Dot11::CONTROL);
    EXPECT_EQ(dot11.subtype(), Dot11::ACK);
    EXPECT_EQ(dot11.to_ds(), 1);
    EXPECT_EQ(dot11.from_ds(), 0);
    EXPECT_EQ(dot11.more_frag(), 0);
    EXPECT_EQ(dot11.retry(), 0);
    EXPECT_EQ(dot11.power_mgmt(), 0);
    EXPECT_EQ(dot11.wep(), 0);
    EXPECT_EQ(dot11.order(), 0);
    EXPECT_EQ(dot11.duration_id(), 0x234f);
    EXPECT_EQ(dot11.subtype(), Dot11::ACK);
    EXPECT_EQ(dot11.addr1(), "00:01:02:03:04:05");
}

TEST_F(Dot11AckTest, Constructor) {
    Dot11Ack dot11;
    test_equals_empty(static_cast<const Dot11&>(dot11));
    EXPECT_EQ(dot11.protocol(), 0);
    EXPECT_EQ(dot11.type(), Dot11::CONTROL);
    EXPECT_EQ(dot11.subtype(), Dot11::ACK);
    EXPECT_EQ(dot11.to_ds(), 0);
    EXPECT_EQ(dot11.from_ds(), 0);
    EXPECT_EQ(dot11.more_frag(), 0);
    EXPECT_EQ(dot11.retry(), 0);
    EXPECT_EQ(dot11.power_mgmt(), 0);
    EXPECT_EQ(dot11.wep(), 0);
    EXPECT_EQ(dot11.order(), 0);
    EXPECT_EQ(dot11.duration_id(), 0);
    EXPECT_EQ(dot11.addr1(), empty_addr);
}

TEST_F(Dot11AckTest, ConstructorFromBuffer) {
    Dot11Ack dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11AckTest, CopyConstructor) {
    Dot11Ack dot1(expected_packet, sizeof(expected_packet));
    Dot11Ack dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11AckTest, CopyAssignmentOperator) {
    Dot11Ack dot1(expected_packet, sizeof(expected_packet));
    Dot11Ack dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11AckTest, ClonePDU) {
    Dot11Ack dot1(expected_packet, sizeof(expected_packet));
    Internals::smart_ptr<Dot11Ack>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11AckTest, FromBytes) {
    Internals::smart_ptr<PDU>::type dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11Ack *inner = dot11->find_pdu<Dot11Ack>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

TEST_F(Dot11AckTest, Serialize) {
    Dot11Ack pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

#endif // HAVE_DOT11
