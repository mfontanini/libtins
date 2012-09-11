#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
#include "tests/dot11.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11PSPollTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11PSPollTest::expected_packet[] = { 
    '\xa5', '\x01', 'O', '#', '\x00', '\x01', '\x02', '\x03', '\x04', 
    '\x05', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06'
};

void test_equals(const Dot11PSPoll &dot1, const Dot11PSPoll &dot2) {
    test_equals(
        static_cast<const Dot11ControlTA&>(dot1),
        static_cast<const Dot11ControlTA&>(dot2)
    );
}

void test_equals_expected(const Dot11PSPoll &dot11) {
    test_equals_expected(static_cast<const Dot11ControlTA&>(dot11));
    EXPECT_EQ(dot11.subtype(), Dot11::PS);
}

TEST_F(Dot11PSPollTest, Constructor) {
    Dot11PSPoll dot11;
    test_equals_empty(static_cast<const Dot11ControlTA&>(dot11));
    EXPECT_EQ(dot11.subtype(), Dot11::PS);
}

TEST_F(Dot11PSPollTest, ConstructorFromBuffer) {
    Dot11PSPoll dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11PSPollTest, CopyConstructor) {
    Dot11PSPoll dot1(expected_packet, sizeof(expected_packet));
    Dot11PSPoll dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11PSPollTest, CopyAssignmentOperator) {
    Dot11PSPoll dot1(expected_packet, sizeof(expected_packet));
    Dot11PSPoll dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11PSPollTest, ClonePDU) {
    Dot11PSPoll dot1(expected_packet, sizeof(expected_packet));
    std::auto_ptr<Dot11PSPoll> dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11PSPollTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11PSPoll *inner = dot11->find_pdu<Dot11PSPoll>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

TEST_F(Dot11PSPollTest, Serialize) {
    Dot11PSPoll pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}
