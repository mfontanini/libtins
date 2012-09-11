#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
#include "tests/dot11.h"

/* PLZ PLZ I need some BLOCK ACK REQUEST packet dump,
 * in order to check the constructor from buffer.
 */


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11BlockAckRequestTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};
/*const uint8_t Dot11BlockAckRequestTest::expected_packet[] = { 
    '\x00', '\x00', ' ', '\x00', 'o', 'H', '\x00', '\x00', 's', 'H', '\xbf', '4', '\x00', '\x00', '\x00', '\x00', '\x10', '\x02', 'l', '\t', '\xdf', '\x00', '\xdc', '\xe0', '\x01', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xfb', '\x00', '\xcf', '\x01', '\x00', '!', 'k', '\x02', '\xe5', '\x99', '\x00', '\x1c', '\xa0', '\xa8', '\r', 'U', '\x04', '\x00', '\xcf', '!', '\xc7', '\xf3', '\x00', ';' 
};*/

void test_equals(const Dot11BlockAckRequest &dot1, const Dot11BlockAckRequest &dot2) {
    EXPECT_EQ(dot1.fragment_number(), dot2.fragment_number());
    EXPECT_EQ(dot1.start_sequence(), dot2.start_sequence());
    EXPECT_EQ(dot1.bar_control(), dot2.bar_control());
    
}

void test_equals_expected(const Dot11BlockAckRequest &dot11) {
    EXPECT_EQ(dot11.type(), Dot11::CONTROL);
    EXPECT_EQ(dot11.subtype(), Dot11::BLOCK_ACK_REQ);
    EXPECT_EQ(dot11.fragment_number(), 6);
    EXPECT_EQ(dot11.start_sequence(), 0x294);
    EXPECT_EQ(dot11.bar_control(), 0x92f);
}

TEST_F(Dot11BlockAckRequestTest, Constructor) {
    Dot11BlockAckRequest dot11;
    test_equals_empty(static_cast<const Dot11ControlTA&>(dot11));
    EXPECT_EQ(dot11.subtype(), Dot11::BLOCK_ACK_REQ);
    EXPECT_EQ(dot11.fragment_number(), 0);
    EXPECT_EQ(dot11.start_sequence(), 0);
    EXPECT_EQ(dot11.bar_control(), 0);
}

/*TEST_F(Dot11BlockAckRequestTest, ConstructorFromBuffer) {
    Dot11BlockAckRequest dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}*/


TEST_F(Dot11BlockAckRequestTest, CopyConstructor) {
    Dot11BlockAckRequest dot1;
    dot1.fragment_number(6);
    dot1.start_sequence(0x294);
    dot1.bar_control(0x92f);
    Dot11BlockAckRequest dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11BlockAckRequestTest, CopyAssignmentOperator) {
    Dot11BlockAckRequest dot1;
    dot1.fragment_number(6);
    dot1.start_sequence(0x294);
    dot1.bar_control(0x92f);
    Dot11BlockAckRequest dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11BlockAckRequestTest, ClonePDU) {
    Dot11BlockAckRequest dot1;
    dot1.fragment_number(6);
    dot1.start_sequence(0x294);
    dot1.bar_control(0x92f);
    std::auto_ptr<Dot11BlockAckRequest> dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

/*TEST_F(Dot11BlockAckRequestTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11BlockAckRequest *inner = dot11->find_inner_pdu<Dot11BlockAckRequest>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}*/

/*TEST_F(Dot11BlockAckRequestTest, Serialize) {
    Dot11BlockAckRequest pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}*/
